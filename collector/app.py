#!/usr/bin/env python3
"""
gp-monitor collector + web.
- Interroga i server via SSH (chiave dedicata, comando forzato = sola sonda).
- Calcola i rate dai contatori (rete, pacchetti droppati dal firewall).
- Salva una storia compatta in SQLite con retention limitata.
- Espone /api/latest, /api/history e la dashboard su una porta bindata su rete fidata.
Solo stdlib.
"""
import base64
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
import statistics
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
# Security Activity Index engine (funzioni pure, testabili senza DB/SSH)
from sai_engine import (
    SAI_WEIGHTS, SECURITY_THRESHOLDS, SAI_HYSTERESIS, SENSITIVE_PORTS,
    safe_rate as _safe_rate, baseline_values as _baseline_values,
    normalized_ratio as _normalized_ratio, sai_score as _sai_score_impl,
    classify_state as _classify_state_impl,
)

# ---------------------------------------------------------------- versione
VERSION = "v3.0"
BUILD_DATE = "2026-08-23 16:10"
AUTHOR = "Stefano Scaramuzzino"
REPORT_EMAIL = os.environ.get("MON_REPORT_EMAIL", "")


# ---------------------------------------------------------------- config
def parse_hosts(spec):
    # formato: "nome1=utente@host1,nome2=utente@host2" (host = IP o hostname raggiungibile in SSH)
    hosts = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        name, target = chunk.split("=", 1)
        hosts.append((name.strip(), target.strip()))
    return hosts


ENV_HOSTS = parse_hosts(os.environ.get("MON_HOSTS", ""))
BIND = os.environ.get("MON_BIND", "127.0.0.1:8888")
INTERVAL = int(os.environ.get("MON_INTERVAL", "15"))
RETENTION_H = int(os.environ.get("MON_RETENTION_HOURS", "48"))
SSH_KEY = os.environ.get("MON_SSH_KEY", "/app/ssh/monitor_ed25519")
DATA_DIR = os.environ.get("MON_DATA_DIR", "/app/data")
# --- scansione nmap (agentless, on-premise) ---
NMAP_ENABLED = os.environ.get("MON_NMAP", "1") not in ("0", "false", "no", "")
NMAP_INTERVAL_H = int(os.environ.get("MON_NMAP_INTERVAL_HOURS", "6"))   # rescan automatico ogni N ore
NMAP_TOP_PORTS = int(os.environ.get("MON_NMAP_TOP_PORTS", "1000"))      # profondità standard
NMAP_DEEP = os.environ.get("MON_NMAP_DEEP", "0") not in ("0", "false", "no", "")  # tutte le 65535 porte
# NB: vulners interroga vulners.com via internet (CPE->CVE) -> NON è più on-premise
NMAP_VULN = os.environ.get("MON_NMAP_VULN", "0") not in ("0", "false", "no", "")
# tetto CVE per porta (0 = nessun tetto -> conteggi onesti; >0 = limita per payload)
NMAP_VULN_CAP = int(os.environ.get("MON_NMAP_VULN_CAP", "0"))
# --- Security Activity Dashboard (SAI) ---
# Retention degli eventi security (coerente con le metriche). Configurabile.
SECURITY_RETENTION_H = int(os.environ.get("MON_SECURITY_RETENTION_HOURS", "48"))
DB_PATH = os.path.join(DATA_DIR, "metrics.db")
KNOWN_HOSTS = os.path.join(DATA_DIR, "known_hosts")
HOSTS_FILE = os.path.join(DATA_DIR, "hosts.json")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
HERE = os.path.dirname(os.path.abspath(__file__))
PROBE_LOCAL = os.path.join(HERE, "monitor-probe.py")

BIND_HOST, _, BIND_PORT = BIND.partition(":")
BIND_PORT = int(BIND_PORT or "8888")

# validazione input della config
NAME_RE = re.compile(r"^[A-Za-z0-9 _.-]{1,32}$")
TARGET_RE = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9._:-]{2,}$")
USER_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
FORCED_CMD = "/usr/local/bin/monitor-probe.py"

# ---------------------------------------------------------------- auth
SESSION_TTL = 7 * 24 * 3600     # 7 giorni
PBKDF_ITERS = 200_000
COOKIE = "gpmon_session"
_users_lock = threading.Lock()
USERS = {}      # username -> {salt, hash, role, status, created}
SECRET = b""    # chiave per firmare i cookie di sessione (persistita)

# ---------------------------------------------------------------- state
_lock = threading.Lock()
_latest = {}   # name -> enriched snapshot (dict) or {"error": ...}
_prev = {}     # name -> (ts, {counters}) per il calcolo dei rate
HOSTS = []     # [(name, target)] — lista viva, modificabile a caldo dalla config
_scan_lock = threading.Lock()
_scans_running = set()   # nomi host con una scansione nmap in corso

# ---------------------------------------------------------------- Security Activity Index (SAI)
# SAI = Security Activity Index: intensita' (0-100) dell'attivita' di sicurezza
# anomala osservata sull'host nel periodo corrente. NON e' probabilita' di
# compromissione, NON e' risk score, NON e' CVSS severity. Rappresenta solo
# quanto l'attivita' osservata si discosta dalla baseline dell'host.
# Costanti e funzioni pure in sai_engine.py (importato sopra) per test isolati.
# Deduplicazione eventi: cooldown per non generare un evento ogni 15s durante
# lo stesso attacco. Tipo evento -> secondi di cooldown.
EVENT_COOLDOWN_S = {
    "firewall_spike": 300,
    "ssh_failed_spike": 300,
    "ssh_invalid_spike": 300,
    "fail2ban_ban": 300,
    "new_listen_port": 3600,       # una volta per porta
    "removed_listen_port": 3600,
    "new_inbound_peer": 3600,
    "new_outbound_peer": 3600,
    "connection_spike": 300,
    "scan_exposure_change": 3600,
    "cve_change": 3600,
    "host_security_unknown": 900,
}
# Stato security per-host in memoria (non persistito: ricalcolato a caldo).
# _sec_state[host] = {"state": str, "sai": int, "below_count": int, "last_event_ts": {type: ts}}
_sec_state = {}
_sec_lock = threading.Lock()


def save_hosts():
    """Riscrive la tabella hosts in SQLite (poche righe: delete+insert in transazione)."""
    now = int(time.time())
    with db() as c:
        c.execute("DELETE FROM hosts")
        c.executemany(
            "INSERT INTO hosts (name, target, added) VALUES (?,?,?)",
            [(n, t, now) for n, t in HOSTS],
        )


def _migrate_json(path):
    """Se esiste un vecchio file JSON, lo legge e lo rinomina .migrated (una volta)."""
    try:
        with open(path) as f:
            d = json.load(f)
        os.replace(path, path + ".migrated")
        return d
    except Exception:
        return None


def load_hosts():
    """Carica gli host da SQLite; migra da hosts.json e altrimenti semina da MON_HOSTS."""
    global HOSTS
    with db() as c:
        rows = c.execute("SELECT name, target FROM hosts").fetchall()
    HOSTS = [(r["name"], r["target"]) for r in rows]
    if not HOSTS:  # DB vuoto: prova a migrare il vecchio hosts.json
        arr = _migrate_json(HOSTS_FILE)
        if arr:
            HOSTS = [(h["name"], h["target"]) for h in arr if h.get("name") and h.get("target")]
    if not HOSTS:
        HOSTS = list(ENV_HOSTS)
    save_hosts()


def read_pubkey():
    try:
        with open(SSH_KEY + ".pub") as f:
            return f.read().strip()
    except Exception:
        return None


def read_probe_src():
    try:
        with open(PROBE_LOCAL) as f:
            return f.read()
    except Exception:
        return None


# --- utenti / sessioni --------------------------------------------------
def save_users():
    """Riscrive utenti + segreto di firma in SQLite (delete+insert in transazione)."""
    with db() as c:
        c.execute("DELETE FROM users")
        c.executemany(
            "INSERT INTO users (username,salt,hash,role,status,created) VALUES (?,?,?,?,?,?)",
            [(un, r["salt"], r["hash"], r["role"], r["status"], r.get("created"))
             for un, r in USERS.items()],
        )
        c.execute("INSERT OR REPLACE INTO kv (k, v) VALUES ('secret', ?)", (SECRET.decode(),))


def load_users():
    """Carica utenti + segreto da SQLite; migra da users.json e genera il segreto se assente."""
    global USERS, SECRET
    with db() as c:
        rows = c.execute("SELECT username,salt,hash,role,status,created FROM users").fetchall()
        secrow = c.execute("SELECT v FROM kv WHERE k='secret'").fetchone()
    USERS = {r["username"]: {"salt": r["salt"], "hash": r["hash"], "role": r["role"],
                             "status": r["status"], "created": r["created"]} for r in rows}
    SECRET = secrow["v"].encode() if secrow and secrow["v"] else b""
    if not USERS and not SECRET:  # DB vuoto: prova a migrare il vecchio users.json
        d = _migrate_json(USERS_FILE)
        if d:
            USERS = d.get("users", {}) or {}
            sec = d.get("secret")
            SECRET = sec.encode() if sec else b""
    if not SECRET:
        SECRET = secrets.token_hex(32).encode()
    save_users()  # persiste segreto/migrazione


def set_setting(k, v):
    with db() as c:
        c.execute("INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)", (k, v))


def load_settings():
    """Impostazioni runtime persistite in kv. Al primo avvio semina da env."""
    global NMAP_VULN, REPORT_EMAIL
    with db() as c:
        row = c.execute("SELECT v FROM kv WHERE k='nmap_vuln'").fetchone()
        rowe = c.execute("SELECT v FROM kv WHERE k='report_email'").fetchone()
    if row is None:
        set_setting("nmap_vuln", "1" if NMAP_VULN else "0")  # semina dal default env
    else:
        NMAP_VULN = (row["v"] == "1")
    if rowe is None:
        set_setting("report_email", REPORT_EMAIL)             # semina dal default env
    elif rowe["v"]:
        REPORT_EMAIL = rowe["v"]


def hash_pw(pw, salt_hex):
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt_hex), PBKDF_ITERS)
    return dk.hex()


def make_user(username, pw, role, status):
    salt = secrets.token_hex(16)
    USERS[username] = {
        "salt": salt, "hash": hash_pw(pw, salt),
        "role": role, "status": status, "created": int(time.time()),
    }


def check_pw(rec, pw):
    try:
        return hmac.compare_digest(rec["hash"], hash_pw(pw, rec["salt"]))
    except Exception:
        return False


def make_token(username):
    exp = int(time.time()) + SESSION_TTL
    payload = "%s|%d" % (username, exp)
    sig = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode((payload + "|" + sig).encode()).decode()


def verify_token(tok):
    try:
        raw = base64.urlsafe_b64decode(tok.encode()).decode()
        username, exp, sig = raw.rsplit("|", 2)
        good = hmac.new(SECRET, ("%s|%s" % (username, exp)).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(good, sig):
            return None
        if int(exp) < int(time.time()):
            return None
        rec = USERS.get(username)
        if not rec or rec.get("status") != "active":
            return None
        return username
    except Exception:
        return None


def cookie_str(token, maxage=SESSION_TTL):
    return "%s=%s; HttpOnly; Path=/; Max-Age=%d; SameSite=Lax" % (COOKIE, token, maxage)


# --- enrollment (installazione automatica della sonda) ------------------
def _sshpass_common():
    return [
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "UserKnownHostsFile=%s" % KNOWN_HOSTS,
        "-o", "ConnectTimeout=12",
        "-o", "PreferredAuthentications=password,keyboard-interactive",
        "-o", "PubkeyAuthentication=no",
        "-o", "NumberOfPasswordPrompts=1",
    ]


def enroll_server(target, password):
    """Installa la sonda sul target usando una password di bootstrap USA-E-GETTA
    (mai persistita): copia la sonda, la mette in /usr/local/bin, aggiunge la riga
    a comando forzato per la chiave di monitoraggio, e verifica. Ritorna (ok, msg)."""
    pub = read_pubkey()
    probe = read_probe_src()
    if not pub:
        return False, "chiave pubblica di monitoraggio non trovata nel collector"
    if not probe:
        return False, "sorgente della sonda non trovato nel collector"
    user = target.split("@", 1)[0]
    is_root = (user == "root")
    forced = FORCED_CMD if is_root else ("sudo " + FORCED_CMD)
    akline = ('command="%s",no-agent-forwarding,no-port-forwarding,no-pty,'
              'no-user-rc,no-X11-forwarding %s' % (forced, pub))
    env = dict(os.environ, SSHPASS=password)

    # Passo A (senza sudo): scrive la sonda in /tmp e autorizza la chiave di monitoraggio.
    # stdin = sorgente della sonda; sshpass fornisce la password SSH via env.
    script_a = (
        "set -e; "
        "cat > /tmp/gpmon-probe.py; chmod 755 /tmp/gpmon-probe.py; "
        "mkdir -p ~/.ssh; chmod 700 ~/.ssh; "
        "touch ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys; "
        "grep -qF %s ~/.ssh/authorized_keys || printf '%%s\\n' %s >> ~/.ssh/authorized_keys"
        % (_shq(pub), _shq(akline))
    )
    try:
        a = subprocess.run(["sshpass", "-e", "ssh"] + _sshpass_common() + [target, script_a],
                           capture_output=True, text=True, timeout=40, env=env, input=probe)
    except FileNotFoundError:
        return False, "sshpass non installato nel collector (aggiungilo all'immagine)"
    except Exception as e:
        return False, "connessione fallita: %s" % str(e)[:200]
    if a.returncode != 0:
        return False, "bootstrap fallito: %s" % ((a.stderr or "rc=%d" % a.returncode).strip()[:250])

    # Passo B: installa in /usr/local/bin (+ sudoers NOPASSWD se non root).
    # Se non root, sudo -S legge la password da stdin (usata una sola volta).
    if is_root:
        script_b = ("install -m 755 /tmp/gpmon-probe.py %s && rm -f /tmp/gpmon-probe.py" % FORCED_CMD)
        stdin_b = None
    else:
        script_b = (
            "sudo -S -p '' install -m 755 /tmp/gpmon-probe.py %s; "
            "printf '%%s\\n' %s | sudo -n tee /etc/sudoers.d/gpmon >/dev/null; "
            "sudo -n chmod 440 /etc/sudoers.d/gpmon; "
            "rm -f /tmp/gpmon-probe.py"
            % (FORCED_CMD, _shq("%s ALL=(root) NOPASSWD: %s" % (user, FORCED_CMD)))
        )
        stdin_b = password + "\n"
    try:
        b = subprocess.run(["sshpass", "-e", "ssh"] + _sshpass_common() + [target, script_b],
                           capture_output=True, text=True, timeout=40, env=env, input=stdin_b)
    except Exception as e:
        return False, "installazione fallita: %s" % str(e)[:200]
    if b.returncode != 0:
        return False, "installazione fallita: %s" % ((b.stderr or "rc=%d" % b.returncode).strip()[:250])

    # Verifica finale: interroga la sonda con la chiave di monitoraggio (comando forzato).
    try:
        data = ssh_probe(target)
        if not isinstance(data, dict) or "host" not in data:
            return False, "sonda installata ma risposta non valida in verifica"
    except Exception as e:
        return False, "sonda installata ma verifica fallita: %s" % str(e)[:200]
    return True, "sonda installata e verificata (host=%s)" % data.get("host", "?")


def _shq(s):
    """Quoting sicuro per shell POSIX (single-quote)."""
    return "'" + str(s).replace("'", "'\\''") + "'"


def db():
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")  # scritture concorrenti (poll parallelo)
    return conn


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    with db() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                host TEXT NOT NULL,
                ts INTEGER NOT NULL,
                mem_used INTEGER, mem_total INTEGER,
                disk_pct INTEGER,
                net_rx_rate REAL, net_tx_rate REAL,
                fw_drop_rate REAL,
                estab INTEGER,
                ssh_failed_1h INTEGER,
                f2b_banned INTEGER,
                cont_running INTEGER, cont_total INTEGER
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_metrics_host_ts ON metrics(host, ts)")
        # migrazione: colonne docker aggregate (util CPU% e MEM%) per lo storico del pannello Docker
        have = {r["name"] for r in c.execute("PRAGMA table_info(metrics)")}
        for col in ("dock_cpu", "dock_mem"):
            if col not in have:
                c.execute("ALTER TABLE metrics ADD COLUMN %s REAL" % col)
        # migrazione: colonne security estese per la Security Activity Dashboard.
        # ssh_invalid_1h, f2b_total_failed, in_peers, out_peers, listening_count
        # non erano persistiti (restavano solo in _latest in memoria). Ora li
        # salviamo per calcolare baseline e delta lato collector.
        for col, decl in (("ssh_invalid_1h", "INTEGER"),
                          ("f2b_total_failed", "INTEGER"),
                          ("in_peers", "INTEGER"),
                          ("out_peers", "INTEGER"),
                          ("listening_count", "INTEGER"),
                          ("sai", "INTEGER")):
            if col not in have:
                c.execute("ALTER TABLE metrics ADD COLUMN %s %s" % (col, decl))
        # persistenza consolidata in SQLite (prima erano hosts.json / users.json)
        c.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                name TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                added INTEGER
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt TEXT NOT NULL, hash TEXT NOT NULL,
                role TEXT NOT NULL, status TEXT NOT NULL,
                created INTEGER
            )
        """)
        c.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)")
        # scansioni nmap: una riga (l'ultima) per host
        c.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                host TEXT PRIMARY KEY,
                ts INTEGER,
                duration REAL,
                status TEXT,
                json TEXT
            )
        """)
        # --- Security Activity Dashboard: tabelle derivate ---
        # Eventi security deduplicati (timeline "Security Changes").
        c.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                host TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                value REAL,
                baseline REAL,
                details_json TEXT NOT NULL DEFAULT '{}'
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_security_events_host_ts ON security_events(host, ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_security_events_ts ON security_events(ts)")
        # Peer di rete osservati per host (per rilevare new/rare peer).
        c.execute("""
            CREATE TABLE IF NOT EXISTS security_peers (
                host TEXT NOT NULL,
                direction TEXT NOT NULL,
                ip TEXT NOT NULL,
                port INTEGER,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                max_connections INTEGER DEFAULT 0,
                PRIMARY KEY(host, direction, ip, port)
            )
        """)
        # Porte in ascolto osservate per host (per rilevare new/removed port).
        c.execute("""
            CREATE TABLE IF NOT EXISTS security_ports (
                host TEXT NOT NULL,
                proto TEXT NOT NULL,
                addr TEXT NOT NULL,
                port INTEGER NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                PRIMARY KEY(host, proto, addr, port)
            )
        """)


# ---------------------------------------------------------------- poller
def ssh_probe(target):
    cmd = [
        "ssh", "-i", SSH_KEY,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "UserKnownHostsFile=%s" % KNOWN_HOSTS,
        "-o", "ConnectTimeout=8",
        target, "probe",  # ignorato: scatta il comando forzato lato server
    ]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if p.returncode != 0:
        raise RuntimeError((p.stderr or "ssh rc=%d" % p.returncode).strip()[:300])
    return json.loads(p.stdout)


def public_iface(nets):
    for n in nets:
        if n["iface"] == "eth0":
            return n
    return nets[0] if nets else None


def enrich(name, data):
    """Aggiunge i rate confrontando con la lettura precedente."""
    ts = data["ts"]
    pub = public_iface(data.get("net") or [])
    fw = (data.get("security") or {}).get("fw_dropped_pkts")
    cur = {
        "rx": pub["rx_bytes"] if pub else 0,
        "tx": pub["tx_bytes"] if pub else 0,
        "fw": fw or 0,
    }
    rates = {"net_rx_rate": 0.0, "net_tx_rate": 0.0, "fw_drop_rate": 0.0}
    with _lock:
        prev = _prev.get(name)
        _prev[name] = (ts, cur)
    if prev:
        pts, pc = prev
        dt = ts - pts
        if dt > 0:
            rates["net_rx_rate"] = max(0.0, (cur["rx"] - pc["rx"]) / dt)
            rates["net_tx_rate"] = max(0.0, (cur["tx"] - pc["tx"]) / dt)
            rates["fw_drop_rate"] = max(0.0, (cur["fw"] - pc["fw"]) / dt) * 60.0  # pkt/min
    data["rates"] = rates
    data["public_iface"] = pub["iface"] if pub else None
    return data


def persist(name, data):
    disks = data.get("disk") or []
    root = next((d for d in disks if d["target"] == "/"), (disks[0] if disks else None))
    sec = data.get("security") or {}
    conts = data.get("docker")
    running = sum(1 for c in (conts or []) if c.get("state") == "running")
    total = len(conts) if conts is not None else None
    # aggregati docker per lo storico: util CPU% (normalizzata sui core) e util MEM%
    dock_cpu = dock_mem = None
    if conts:
        cpu_sum = sum((c.get("cpu_pct") or 0) for c in conts)
        cpus = data.get("cpus")
        dock_cpu = (cpu_sum / cpus) if cpus else cpu_sum
        dock_mem = sum((c.get("mem_pct") or 0) for c in conts)
    # security estesa: peers e porte in ascolto (conteggi per lo storico SAI)
    flows = data.get("flows") or {}
    listening = sec.get("listening") or []
    r = data["rates"]
    with db() as c:
        c.execute(
            "INSERT INTO metrics (host,ts,mem_used,mem_total,disk_pct,net_rx_rate,"
            "net_tx_rate,fw_drop_rate,estab,ssh_failed_1h,f2b_banned,cont_running,cont_total,"
            "dock_cpu,dock_mem,ssh_invalid_1h,f2b_total_failed,in_peers,out_peers,listening_count) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (name, data["ts"], data["ram"]["used"], data["ram"]["total"],
             (root["use_pct"] if root else None),
             r["net_rx_rate"], r["net_tx_rate"], r["fw_drop_rate"],
             (data.get("conns") or {}).get("estab"),
             sec.get("ssh_failed_1h"), sec.get("f2b_banned"),
             running, total, dock_cpu, dock_mem,
             sec.get("ssh_invalid_1h"), sec.get("f2b_total_failed"),
             flows.get("in_peers"), flows.get("out_peers"), len(listening)),
        )
        cutoff = int(time.time()) - RETENTION_H * 3600
        c.execute("DELETE FROM metrics WHERE ts < ?", (cutoff,))
        # retention eventi security (coerente con metriche)
        sec_cutoff = int(time.time()) - SECURITY_RETENTION_H * 3600
        c.execute("DELETE FROM security_events WHERE ts < ?", (sec_cutoff,))


def _poll_host(name, target):
    try:
        data = ssh_probe(target)
        data = enrich(name, data)
        with _lock:
            _latest[name] = data
        persist(name, data)
        security_analyze(name, data)   # Security Activity Dashboard (collector-side)
    except Exception as e:
        with _lock:
            _latest[name] = {"name": name, "error": str(e), "ts": int(time.time())}


# ---------------------------------------------------------------- Security Activity Index (SAI) engine
# Tutto collector-side: la sonda resta read-only e invariata. Qui deriviamo
# delta/rate, baseline, SAI, stato e eventi dalle metriche gia' persistite.
# Le funzioni pure (safe_rate, baseline_values, normalized_ratio, sai_score,
# classify_state) sono in sai_engine.py e importate sopra per test isolati.


def _sai_components(host, data, rows):
    """Calcola ogni componente SAI in 0..100. Usa la baseline 1h (piu' reattiva)
    come riferimento principale, con fallback alle soglie assolute se la
    baseline non e' disponibile (host nuovo o pochi campioni)."""
    sec = data.get("security") or {}
    flows = data.get("flows") or {}
    r = data.get("rates") or {}
    now = int(time.time())
    # baseline 1h per le metriche cumulativo-derivate
    bl_fw = _baseline_values(rows, "fw_drop_rate").get(3600, {})
    bl_sshf = _baseline_values(rows, "ssh_failed_1h").get(3600, {})
    bl_sshi = _baseline_values(rows, "ssh_invalid_1h").get(3600, {})
    bl_f2b = _baseline_values(rows, "f2b_banned").get(3600, {})
    # --- firewall: rate pkt/min vs baseline ---
    fw_rate = r.get("fw_drop_rate")
    fw_comp = _normalized_ratio(fw_rate, bl_fw.get("median"))
    # --- ssh failed /h ---
    sshf = sec.get("ssh_failed_1h")
    sshf_comp = _normalized_ratio(sshf, bl_sshf.get("median"))
    # --- ssh invalid /h (segnale piu' forte: scanning/brute) ---
    sshi = sec.get("ssh_invalid_1h")
    sshi_comp = _normalized_ratio(sshi, bl_sshi.get("median"))
    # --- fail2ban: delta banned vs baseline ---
    f2b = sec.get("f2b_banned")
    f2b_comp = _normalized_ratio(f2b, bl_f2b.get("median"))
    # --- new ports: conteggio porte nuove nelle ultime 24h ---
    new_ports = _count_new_ports(host, now - 86400)
    port_comp = min(100, new_ports * SECURITY_THRESHOLDS["new_port_score"])
    # --- network peer anomaly: peer nuovi/rari nelle ultime 6h ---
    peer_anom = _count_new_peers(host, now - 21600)
    peer_comp = min(100, peer_anom * SECURITY_THRESHOLDS["peer_anomaly_score"])
    return {
        "firewall": fw_comp,
        "ssh_failed": sshf_comp,
        "ssh_invalid": sshi_comp,
        "fail2ban": f2b_comp,
        "new_ports": port_comp,
        "network_peer": peer_comp,
        # contesto grezzo per API e drawer
        "_raw": {
            "fw_rate": fw_rate, "ssh_failed_1h": sshf, "ssh_invalid_1h": sshi,
            "f2b_banned": f2b, "new_ports": new_ports, "peer_anomaly": peer_anom,
            "bl_fw": bl_fw.get("median"), "bl_sshf": bl_sshf.get("median"),
            "bl_sshi": bl_sshi.get("median"), "bl_f2b": bl_f2b.get("median"),
        },
        "_available": {
            "firewall": fw_rate is not None,
            "ssh_failed": sshf is not None,
            "ssh_invalid": sshi is not None,
            "fail2ban": f2b is not None,
            "new_ports": True,
            "network_peer": True,
        },
    }


def _sai_score(components):
    """Wrapper per sai_engine.sai_score (vedi sai_engine.py per i test)."""
    return _sai_score_impl(components)


def _classify_state(host, sai, components, raw):
    """Classifica lo stato con hysteresis per evitare oscillazioni ogni 15s.
    Delega la logica pura a sai_engine.classify_state; qui gestisce solo lo
    stato in-memory per-host (protetto da _sec_lock). ACTIVE ATTACK richiede
    SAI alto AND almeno una rule composita (non basta il SAI da solo). Mai
    usare COMPROMISED/INFECTED/BREACHED: GPMonitor non ha le evidenze."""
    with _sec_lock:
        st = _sec_state.setdefault(host, {"state": "unknown", "sai": 0,
                                          "below_count": 0, "last_event_ts": {}})
        return _classify_state_impl(st["state"], sai, raw, st)


def _count_new_ports(host, since):
    """Porte in ascolto apparse dopo `since` (first_seen >= since)."""
    with db() as c:
        return c.execute(
            "SELECT COUNT(*) AS n FROM security_ports WHERE host=? AND first_seen>=?",
            (host, since)).fetchone()["n"]


def _count_new_peers(host, since):
    """Peer di rete apparsi dopo `since` (first_seen >= since)."""
    with db() as c:
        return c.execute(
            "SELECT COUNT(*) AS n FROM security_peers WHERE host=? AND first_seen>=?",
            (host, since)).fetchone()["n"]


def _emit_event(host, event_type, severity, value=None, baseline=None, details=None):
    """Inserisce un evento security con deduplicazione via cooldown. Se esiste
    gia' un evento dello stesso tipo per l'host entro il cooldown, non ne
    creiamo un altro (evita un evento ogni 15s durante lo stesso attacco)."""
    now = int(time.time())
    cd = EVENT_COOLDOWN_S.get(event_type, 300)
    with db() as c:
        last = c.execute(
            "SELECT ts FROM security_events WHERE host=? AND event_type=? "
            "ORDER BY ts DESC LIMIT 1", (host, event_type)).fetchone()
        if last and (now - last["ts"]) < cd:
            return False  # deduplicato: dentro cooldown
        c.execute(
            "INSERT INTO security_events (ts, host, event_type, severity, value, "
            "baseline, details_json) VALUES (?,?,?,?,?,?,?)",
            (now, host, event_type, severity, value, baseline,
             json.dumps(details or {})))
        return True


def _detect_port_changes(host, listening, now):
    """Rileva new/removed listen port confrontando con lo storico security_ports.
    Aggiorna first_seen/last_seen. Una porta e' 'nuova' se first_seen e' adesso
    (non era mai stata osservata). Una porta 'rimossa' se non e' nel campione
    corrente ma era nello storico con last_seen recente."""
    current = set()
    for p in (listening or []):
        proto = p.get("proto") or ""
        addr = p.get("addr") or ""
        port = int(p.get("port") or 0)
        if port <= 0:
            continue
        current.add((proto, addr, port))
    with db() as c:
        known = {row["key"] for row in c.execute(
            "SELECT proto||'|'||addr||'|'||port AS key FROM security_ports WHERE host=?",
            (host,))}
        # nuove porte
        for proto, addr, port in current - known:
            c.execute(
                "INSERT INTO security_ports (host,proto,addr,port,first_seen,last_seen) "
                "VALUES (?,?,?,?,?,?)", (host, proto, addr, port, now, now))
            sev = "high" if port in SENSITIVE_PORTS else "medium"
            _emit_event(host, "new_listen_port", sev,
                        value=port, details={"proto": proto, "addr": addr, "port": port,
                                             "sensitive": port in SENSITIVE_PORTS})
        # porte confermate (update last_seen)
        for proto, addr, port in current & known:
            c.execute(
                "UPDATE security_ports SET last_seen=? WHERE host=? AND proto=? AND addr=? AND port=?",
                (now, host, proto, addr, port))
        # porte rimosse (presenti nello storico, non nel campione, last_seen recente)
        for proto, addr, port in known - current:
            c.execute(
                "UPDATE security_ports SET last_seen=? WHERE host=? AND proto=? AND addr=? AND port=?",
                (now - 1, host, proto, addr, port))


def _detect_peer_anomalies(host, flows, now):
    """Rileva new inbound/outbound peer aggiornando security_peers. Un peer e'
    'nuovo' se non era mai stato osservato (first_seen = now). Non dichiariamo
    il peer malicious: usiamo terminologia 'new'/'rare' (salvo evidenza esterna)."""
    for direction in ("in", "out"):
        for peer in (flows or {}).get(direction, []):
            ip = peer.get("ip")
            port = int(peer.get("port") or 0)
            n = int(peer.get("n") or 0)
            if not ip or port <= 0:
                continue
            with db() as c:
                row = c.execute(
                    "SELECT first_seen, last_seen, max_connections FROM security_peers "
                    "WHERE host=? AND direction=? AND ip=? AND port=?",
                    (host, direction, ip, port)).fetchone()
                if row is None:
                    c.execute(
                        "INSERT INTO security_peers (host,direction,ip,port,first_seen,"
                        "last_seen,max_connections) VALUES (?,?,?,?,?,?,?)",
                        (host, direction, ip, port, now, now, n))
                    _emit_event(host, "new_%bound_peer" % direction, "medium",
                                details={"ip": ip, "port": port, "direction": direction,
                                         "n": n})
                else:
                    c.execute(
                        "UPDATE security_peers SET last_seen=?, max_connections=? "
                        "WHERE host=? AND direction=? AND ip=? AND port=?",
                        (now, max(row["max_connections"], n), host, direction, ip, port))


def _detect_spikes(host, data, rows, raw, bl):
    """Rileva spike rispetto alla baseline per firewall/ssh/fail2ban. Usa
    baseline relativa (current > baseline * multiplier) con un minimo assoluto
    per non scatenare spike su baseline 0 con rumore minimo."""
    th = SECURITY_THRESHOLDS
    now = int(time.time())
    # firewall spike
    fw = raw["fw_rate"]
    if fw is not None and fw >= th["spike_min_absolute"]:
        b = bl.get("bl_fw")
        if b is not None and fw > b * th["spike_multiplier"]:
            _emit_event(host, "firewall_spike", "high", value=fw, baseline=b,
                        details={"rate_per_min": fw, "baseline": b})
        elif b is None and fw >= th["firewall_rate_high"]:
            _emit_event(host, "firewall_spike", "high", value=fw, baseline=None,
                        details={"rate_per_min": fw, "baseline": "n/a (host nuovo)"})
    # ssh failed spike
    sshf = raw["ssh_failed_1h"]
    if sshf is not None and sshf >= th["spike_min_absolute"]:
        b = bl.get("bl_sshf")
        if b is not None and sshf > b * th["spike_multiplier"]:
            _emit_event(host, "ssh_failed_spike", "high", value=sshf, baseline=b)
        elif b is None and sshf >= th["ssh_failed_high"]:
            _emit_event(host, "ssh_failed_spike", "high", value=sshf, baseline=None)
    # ssh invalid spike
    sshi = raw["ssh_invalid_1h"]
    if sshi is not None and sshi >= th["ssh_invalid_warn"]:
        b = bl.get("bl_sshi")
        if b is not None and sshi > b * th["spike_multiplier"]:
            _emit_event(host, "ssh_invalid_spike", "high", value=sshi, baseline=b)
        elif b is None and sshi >= th["ssh_invalid_high"]:
            _emit_event(host, "ssh_invalid_spike", "high", value=sshi, baseline=None)
    # fail2ban ban increment
    f2b = raw["f2b_banned"]
    if f2b is not None and f2b > 0:
        b = bl.get("bl_f2b")
        if b is not None and f2b > b:
            _emit_event(host, "fail2ban_ban", "medium", value=f2b, baseline=b,
                        details={"banned": f2b, "baseline": b})


def security_analyze(name, data):
    """Orchestratore della Security Activity Dashboard. Chiamato in _poll_host
    dopo persist. Calcola componenti SAI, score, stato (con hysteresis) e
    rileva eventi (porte, peer, spike). Tutto collector-side, sonda invariata.
    Target: < 100ms/host su carichi normali."""
    try:
        now = int(data.get("ts") or time.time())
        # ultime 24h di metriche per le baseline
        with db() as c:
            # dict (non sqlite3.Row): sai_engine.baseline_values usa r.get(field)
            rows = [dict(r) for r in c.execute(
                "SELECT ts, fw_drop_rate, ssh_failed_1h, ssh_invalid_1h, f2b_banned "
                "FROM metrics WHERE host=? AND ts>=? ORDER BY ts",
                (name, now - 86400)).fetchall()]
        components = _sai_components(name, data, rows)
        sai, weights = _sai_score(components)
        raw = components["_raw"]
        state = _classify_state(name, sai, components, raw)
        # persist SAI nella metrics row appena scritta (update ultima riga)
        with db() as c:
            c.execute("UPDATE metrics SET sai=? WHERE host=? AND ts=?",
                      (sai, name, data["ts"]))
        # detection eventi
        sec = data.get("security") or {}
        flows = data.get("flows") or {}
        _detect_port_changes(name, sec.get("listening"), now)
        _detect_peer_anomalies(name, flows, now)
        _detect_spikes(name, data, rows, raw, raw)
        # stato UNKNOWN se non ci sono abbastanza dati
        if state == "unknown" and not any(components["_available"].values()):
            _emit_event(name, "host_security_unknown", "low",
                        details={"reason": "telemetria security non disponibile"})
    except Exception:
        # nessun errore di telemetria deve rompere il poller
        pass


def poll_once():
    # in parallelo: un server lento/irraggiungibile non blocca gli altri
    threads = []
    for name, target in list(HOSTS):  # snapshot: la lista può cambiare a caldo
        t = threading.Thread(target=_poll_host, args=(name, target), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=35)


def poller_loop():
    while True:
        start = time.time()
        poll_once()
        time.sleep(max(1.0, INTERVAL - (time.time() - start)))


# ---------------------------------------------------------------- scansione nmap
def _target_ip(target):
    """'utente@100.1.2.3' -> '100.1.2.3' (rimuove eventuale :porta)."""
    host = target.split("@", 1)[1] if "@" in target else target
    return host.split(":", 1)[0]


def run_nmap(ip):
    """Scansione nmap: versioni servizi (-sV), OS detection (-O) e script NSE.
    Con NMAP_VULN attivo aggiunge 'vulners' (CPE->CVE via vulners.com, richiede
    internet: NON on-premise). -sS/-O richiedono privilegi raw: il container gira
    root con NET_RAW/NET_ADMIN. I timeout scalano con la profondità (-p-)."""
    scope = ["-p-"] if NMAP_DEEP else ["--top-ports", str(NMAP_TOP_PORTS)]
    scripts = "default,vulners" if NMAP_VULN else "default"
    htimeout = "1500s" if NMAP_DEEP else "300s"
    proc_timeout = 1800 if NMAP_DEEP else 600
    cmd = (["nmap", "-sV", "-O", "-T4", "--script", scripts,
            "--host-timeout", htimeout, "--max-retries", "2", "-oX", "-"] + scope + [ip])
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=proc_timeout)
    if not (p.stdout or "").strip():
        raise RuntimeError((p.stderr or "nmap rc=%d" % p.returncode).strip()[:300])
    return parse_nmap_xml(p.stdout)


def _parse_vulners(script_el):
    """Estrae le CVE dall'output strutturato dello script NSE 'vulners':
    table[key=cpe] > table > elem[key in id/cvss/type/is_exploit]."""
    out = []
    for cpe_tbl in script_el.findall("table"):
        for vt in cpe_tbl.findall("table"):
            d = {e.get("key"): (e.text or "").strip() for e in vt.findall("elem")}
            vid = d.get("id")
            if not vid:
                continue
            cvss = None
            try:
                cvss = float(d["cvss"]) if d.get("cvss") else None
            except ValueError:
                cvss = None
            out.append({"id": vid, "cvss": cvss, "type": d.get("type"),
                        "exploit": d.get("is_exploit") == "true"})
    return out


def _dedup_vulns(vulns):
    """Deduplica per CVE tenendo il CVSS più alto e ordina per gravità.
    Nessun tetto se NMAP_VULN_CAP<=0 (conteggi onesti), altrimenti limita al cap."""
    seen = {}
    for v in vulns:
        k = v["id"]
        if k not in seen or (v.get("cvss") or 0) > (seen[k].get("cvss") or 0):
            seen[k] = v
    arr = sorted(seen.values(), key=lambda x: (-(x.get("cvss") or 0), x["id"]))
    return arr if NMAP_VULN_CAP <= 0 else arr[:NMAP_VULN_CAP]


# mappa prodotto -> pacchetto APT (i server sono Ubuntu): remediation via apt-get.
# NB: l'ordine conta (match per sottostringa): i nomi COMPOSTI/specifici vanno PRIMA
# di quelli generici (es. "tomcat"/"coyote" prima di "apache").
_APT_PKG = [
    # --- SSH / remote ---
    ("openssh", "openssh-server"), ("dropbear", "dropbear"),
    # --- web server / proxy (specifici prima dei generici) ---
    ("tomcat", "tomcat9"), ("coyote", "tomcat9"), ("jetty", "jetty9"),
    ("lighttpd", "lighttpd"), ("haproxy", "haproxy"), ("varnish", "varnish"),
    ("squid", "squid"), ("nginx", "nginx"), ("apache", "apache2"), ("httpd", "apache2"),
    # --- mail ---
    ("postfix", "postfix"), ("exim", "exim4"), ("sendmail", "sendmail"),
    ("dovecot", "dovecot-core"), ("cyrus", "cyrus-imapd"),
    # --- database / cache ---
    ("postgresql", "postgresql"), ("mariadb", "mariadb-server"), ("mysql", "mysql-server"),
    ("redis", "redis-server"), ("memcached", "memcached"), ("mongodb", "mongodb-org-server"),
    ("rabbitmq", "rabbitmq-server"),
    # --- ftp ---
    ("vsftpd", "vsftpd"), ("proftpd", "proftpd-basic"), ("pure-ftpd", "pure-ftpd"),
    # --- rete / infra ---
    ("bind", "bind9"), ("unbound", "unbound"), ("dnsmasq", "dnsmasq"),
    ("isc-dhcp", "isc-dhcp-server"), ("dhcpd", "isc-dhcp-server"),
    ("openvpn", "openvpn"), ("strongswan", "strongswan"), ("openswan", "strongswan"),
    ("ipsec", "strongswan"), ("chrony", "chrony"), ("ntpd", "ntp"), ("ntp", "ntp"),
    ("net-snmp", "snmpd"), ("snmp", "snmpd"), ("rsync", "rsync"), ("samba", "samba"),
    ("cups", "cups"), ("mosquitto", "mosquitto"),
    # --- runtime / linguaggi (aggiornabili via apt su Ubuntu) ---
    ("openssl", "openssl"), ("php", "php"),
]
# prodotti applicativi/dipendenze non gestiti da APT: si aggiornano nel progetto
_APP_HINT = {
    # Python (framework/server WSGI-ASGI; il numero di versione è quello del pacchetto pip)
    "werkzeug":  ("Python", "pip install -U werkzeug     # poi aggiorna requirements.txt e ridispiega"),
    "uvicorn":   ("Python", "pip install -U uvicorn"),
    "gunicorn":  ("Python", "pip install -U gunicorn"),
    "fastapi":   ("Python", "pip install -U fastapi"),
    "starlette": ("Python", "pip install -U starlette"),
    "aiohttp":   ("Python", "pip install -U aiohttp"),
    "tornado":   ("Python", "pip install -U tornado"),
    "twisted":   ("Python", "pip install -U twisted"),
    "flask":     ("Python", "pip install -U flask"),
    "django":    ("Python", "pip install -U django"),
    "cheroot":   ("Python", "pip install -U cheroot cherrypy"),
    "cherrypy":  ("Python", "pip install -U cherrypy"),
    "basehttpserver": ("Python", "è il server stdlib di gp-monitor stesso: aggiorna la base image Python del container (Dockerfile) e ridispiega"),
    "simplehttp":     ("Python", "server http stdlib: aggiorna la base image Python e ridispiega"),
    # Go
    "golang":  ("Go", "aggiorna il modulo/binario Go e ricompila: go get -u ./... && go build"),
    "gin":     ("Go", "aggiorna il modulo Go: go get -u && go build"),
    "traefik": ("Go", "aggiorna l'immagine/binario Traefik (release ufficiali) e ridispiega"),
    "caddy":   ("Go", "aggiorna il binario Caddy (release ufficiali) e ridispiega"),
    "envoy":   ("Go/C++", "aggiorna l'immagine Envoy e ridispiega"),
    "prometheus": ("Go", "aggiorna il binario Prometheus (release ufficiali)"),
    "grafana": ("Go", "aggiorna il pacchetto/immagine Grafana (repo ufficiale)"),
    "consul":  ("Go", "aggiorna il binario Consul (HashiCorp releases)"),
    # Node
    "express": ("Node", "npm update express     # poi ridispiega"),
    "fastify": ("Node", "npm update fastify"),
    "node":    ("Node", "npm update (o aggiorna package.json) e ridispiega"),
    # Ruby / Java / .NET
    "puma":      ("Ruby", "bundle update puma"),
    "passenger": ("Ruby", "gem update passenger / bundle update"),
    "kestrel":   (".NET", "aggiorna il runtime .NET e ripubblica l'app"),
    # container runtime
    "docker":     ("Docker", "aggiorna docker-ce dal repo ufficiale Docker; ricrea i container"),
    "containerd": ("Docker", "aggiorna containerd.io dal repo ufficiale Docker"),
}


def _rem_sev(cvss, exploit):
    if exploit or (cvss or 0) >= 9:
        return "high"
    if (cvss or 0) >= 7:
        return "med"
    return "low"


def build_remediation(result):
    """Genera remediation azionabili DAL risultato dello scan (deterministico, no LLM):
    per ogni servizio con CVE deduce il pacchetto APT o la dipendenza applicativa,
    i comandi concreti e la priorità (exploit noto / CVSS)."""
    if not result:
        return None
    items, total_cve, total_expl = [], 0, 0
    for p in result.get("ports", []):
        vulns = p.get("vulns") or []
        if not vulns:
            continue
        total_cve += len(vulns)
        expl = sum(1 for v in vulns if v.get("exploit"))
        total_expl += expl
        maxc = max((v.get("cvss") or 0) for v in vulns)
        product = (p.get("product") or p.get("service") or "").strip()
        plow = product.lower().replace(" ", "").replace("/", "")
        pkg, kind, cmds = None, "manual", []
        # 1) framework applicativi (più specifici) PRIMA di APT: es. "Werkzeug httpd"
        #    contiene "httpd" ma NON è Apache -> va gestito come dipendenza Python.
        hint = None
        for key, val in _APP_HINT.items():
            if key in plow:
                hint = val
                break
        if not hint:
            for key, pk in _APT_PKG:
                if key in plow:
                    pkg = pk
                    break
        if pkg:
            kind = "apt"
            svc = "ssh" if pkg == "openssh-server" else pkg.split("-")[0]
            cmds = [
                "sudo apt-get update",
                "sudo apt-get install --only-upgrade %s" % pkg,
                "# verifica se la CVE è già chiusa dal backport Ubuntu:",
                "apt-get changelog %s | grep -i cve | head" % pkg,
                "sudo systemctl restart %s" % svc,
            ]
            action = ("Aggiorna **%s** via APT. Ubuntu applica i backport di sicurezza "
                      "mantenendo il numero di versione upstream: se dopo l'update la CVE "
                      "resta segnalata è quasi sempre un **falso positivo**." % pkg)
        elif hint:
            kind = "app"
            cmds = [hint[1]]
            action = ("Servizio applicativo **%s** (%s): non si aggiorna via APT, "
                      "aggiorna la dipendenza nel progetto e ridispiega." % (product, hint[0]))
        else:
            action = ("Identifica il fornitore di **%s** (porta %s) e applica "
                      "l'aggiornamento di sicurezza consigliato." % (product or "servizio", p.get("port")))
        cves = sorted(vulns, key=lambda v: (not v.get("exploit"), -(v.get("cvss") or 0)))
        items.append({
            "sev": _rem_sev(maxc, expl), "port": p.get("port"), "proto": p.get("proto"),
            "service": product or p.get("service"), "pkg": pkg, "kind": kind,
            "max_cvss": maxc, "exploit": expl, "cve_count": len(vulns),
            "action": action, "commands": cmds,
            "cves": [{"id": v["id"], "cvss": v.get("cvss"), "exploit": bool(v.get("exploit"))}
                     for v in cves[:8]],
        })
    order = {"high": 0, "med": 1, "low": 2}
    items.sort(key=lambda x: (order.get(x["sev"], 3), -(x["max_cvss"] or 0)))
    notes = [
        "I rilievi di `vulners` sono **potenziali falsi positivi**: correlano per versione "
        "upstream e NON tengono conto dei backport di Ubuntu (pacchetti `...ubuntuX.Y`). "
        "Verifica sempre con `apt-get changelog <pkg>`.",
        "Dai **priorità** alle CVE con **exploit noto** (⚡) e CVSS ≥ 9.",
        "Base: `sudo apt-get update && sudo apt-get full-upgrade` e reboot se aggiornato il kernel.",
        "Riduci la superficie: filtra/chiudi le porte non necessarie esposte oltre la rete fidata/VPN.",
    ]
    return {"items": items, "notes": notes,
            "totals": {"cve": total_cve, "exploit": total_expl, "services": len(items)}}


def scan_summary(result):
    """Riepilogo per il KPI di sicurezza RAG sulla card: CVE deduplicate per id,
    con conteggio criticità / alte / con-exploit e porte aperte."""
    if not result:
        return None
    seen = {}
    for p in result.get("ports", []):
        for v in (p.get("vulns") or []):
            k = v.get("id")
            c = v.get("cvss") or 0
            e = seen.get(k)
            if e is None or c > (e["cvss"] or 0):
                seen[k] = {"cvss": c, "exploit": bool(v.get("exploit")) or (e["exploit"] if e else False)}
            elif v.get("exploit"):
                seen[k]["exploit"] = True
    vals = list(seen.values())
    return {
        "cve": len(vals),
        "exploit": sum(1 for v in vals if v["exploit"]),
        "critical": sum(1 for v in vals if (v["cvss"] or 0) >= 9),
        "high": sum(1 for v in vals if 7 <= (v["cvss"] or 0) < 9),
        "open_ports": len(result.get("ports", [])),
        "up": bool(result.get("up")),
    }


def parse_nmap_xml(xml_text):
    """Estrae dall'XML di nmap: stato host, indirizzi, hostname, porte (con servizio,
    versione, CPE e script), OS match e script a livello host."""
    root = ET.fromstring(xml_text)
    fin = root.find("runstats/finished")
    out = {
        "up": False, "addresses": [], "hostnames": [], "ports": [], "os": [],
        "hostscripts": [], "extraports": None,
        "elapsed": float(fin.get("elapsed")) if (fin is not None and fin.get("elapsed")) else None,
        "nmap_version": root.get("version"), "args": root.get("args"),
    }
    hostel = root.find("host")
    if hostel is None:
        return out
    st = hostel.find("status")
    out["up"] = (st is not None and st.get("state") == "up")
    for a in hostel.findall("address"):
        out["addresses"].append({"addr": a.get("addr"), "type": a.get("addrtype"),
                                 "vendor": a.get("vendor")})
    hn = hostel.find("hostnames")
    if hn is not None:
        out["hostnames"] = [h.get("name") for h in hn.findall("hostname") if h.get("name")]
    ports = hostel.find("ports")
    if ports is not None:
        ep = ports.find("extraports")
        if ep is not None:
            out["extraports"] = {"state": ep.get("state"), "count": int(ep.get("count") or 0)}
        for p in ports.findall("port"):
            state = p.find("state")
            svc = p.find("service")
            scripts, vulns = [], []
            for s in p.findall("script"):
                scripts.append({"id": s.get("id"), "output": (s.get("output") or "").strip()})
                if (s.get("id") or "").startswith("vulners"):
                    vulns.extend(_parse_vulners(s))
            out["ports"].append({
                "port": int(p.get("portid")),
                "proto": p.get("protocol"),
                "state": state.get("state") if state is not None else None,
                "reason": state.get("reason") if state is not None else None,
                "service": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
                "extrainfo": svc.get("extrainfo") if svc is not None else None,
                "tunnel": svc.get("tunnel") if svc is not None else None,
                "cpe": [c.text for c in (svc.findall("cpe") if svc is not None else [])],
                "scripts": scripts,
                "vulns": _dedup_vulns(vulns),
            })
    # tengo solo le porte non chiuse (open / open|filtered) per la UI
    out["ports"] = [pp for pp in out["ports"] if pp["state"] and pp["state"] != "closed"]
    out["ports"].sort(key=lambda x: x["port"])
    for m in hostel.findall("os/osmatch"):
        out["os"].append({"name": m.get("name"), "accuracy": int(m.get("accuracy") or 0)})
    out["os"].sort(key=lambda x: -x["accuracy"])
    for s in hostel.findall("hostscript/script"):
        out["hostscripts"].append({"id": s.get("id"), "output": (s.get("output") or "").strip()})
    return out


def save_scan(host, status, result, duration):
    now = int(time.time())
    with db() as c:
        c.execute(
            "INSERT OR REPLACE INTO scans (host, ts, duration, status, json) VALUES (?,?,?,?,?)",
            (host, now, duration, status, json.dumps(result) if result is not None else None))


def get_scan(host):
    with db() as c:
        r = c.execute("SELECT ts, duration, status, json FROM scans WHERE host=?", (host,)).fetchone()
    if not r:
        return None
    return {"ts": r["ts"], "duration": r["duration"], "status": r["status"],
            "result": json.loads(r["json"]) if r["json"] else None}


def do_scan(host, target):
    """Esegue una scansione nmap (sincrona) e la persiste. Un solo scan per host alla volta."""
    with _scan_lock:
        if host in _scans_running:
            return
        _scans_running.add(host)
    start = time.time()
    try:
        result = run_nmap(_target_ip(target))
        save_scan(host, "ok", result, round(time.time() - start, 1))
    except Exception as e:
        save_scan(host, "error", {"error": str(e)[:400]}, round(time.time() - start, 1))
    finally:
        with _scan_lock:
            _scans_running.discard(host)


def scan_async(host, target):
    threading.Thread(target=do_scan, args=(host, target), daemon=True).start()


def scan_loop():
    """Scheduler background: rifà la scansione di ogni host quando diventa stantìa
    (> NMAP_INTERVAL_H ore). Sequenziale: una scansione pesante alla volta."""
    if not NMAP_ENABLED:
        return
    time.sleep(25)  # lascia partire poller + web
    while True:
        for name, target in list(HOSTS):
            cur = get_scan(name)
            stale = (cur is None) or (int(time.time()) - cur["ts"] > NMAP_INTERVAL_H * 3600)
            with _scan_lock:
                busy = name in _scans_running
            if stale and not busy:
                do_scan(name, target)
        time.sleep(300)  # ricontrolla ogni 5 min


# ---------------------------------------------------------------- Security Activity Dashboard API
def _security_overview():
    """KPI globali + stato per-host. Compatibile con host down/telemetria
    assente: in quel caso stato=unknown e i campi None (NON 0)."""
    now = int(time.time())
    hosts_out = []
    totals = {"active_attack": 0, "elevated": 0, "normal": 0, "unknown": 0,
              "ssh_failed_1h": 0, "ssh_invalid_1h": 0, "f2b_banned": 0,
              "new_ports": 0, "fw_drop_rate": 0.0}
    for name, _t in list(HOSTS):
        with _lock:
            data = _latest.get(name) or {}
        sec = data.get("security") or {}
        flows = data.get("flows") or {}
        r = data.get("rates") or {}
        with _sec_lock:
            st = _sec_state.get(name, {})
        state = st.get("state", "unknown")
        sai = st.get("sai", 0)
        # conteggio nuove porte ultime 24h
        new_ports = _count_new_ports(name, now - 86400)
        listening = sec.get("listening") or []
        h = {
            "host": name,
            "state": state,
            "sai": sai,
            "firewall_rate": r.get("fw_drop_rate"),
            "ssh_failed_1h": sec.get("ssh_failed_1h"),
            "ssh_invalid_1h": sec.get("ssh_invalid_1h"),
            "f2b_banned": sec.get("f2b_banned"),
            "f2b_total_failed": sec.get("f2b_total_failed"),
            "listening_ports": len(listening),
            "new_ports": new_ports,
            "in_peers": flows.get("in_peers"),
            "out_peers": flows.get("out_peers"),
            "estab": (data.get("conns") or {}).get("estab"),
            "last_ts": data.get("ts"),
            "error": data.get("error"),
        }
        hosts_out.append(h)
        if state in totals:
            totals[state] += 1
        # somme globali (None safe: somma solo se presente)
        if h["ssh_failed_1h"] is not None:
            totals["ssh_failed_1h"] += h["ssh_failed_1h"]
        if h["ssh_invalid_1h"] is not None:
            totals["ssh_invalid_1h"] += h["ssh_invalid_1h"]
        if h["f2b_banned"] is not None:
            totals["f2b_banned"] += h["f2b_banned"]
        totals["new_ports"] += new_ports
        if h["firewall_rate"] is not None:
            totals["fw_drop_rate"] += h["firewall_rate"]
    return {"ts": now, "hosts": hosts_out, "totals": totals}


def _security_history(host, minutes):
    """Serie temporale SAI con bucketing per non spedire migliaia di campioni.
    <=1h raw, <=6h bucket 1m, <=24h bucket 5m, <=48h bucket 10m."""
    mins = max(1, min(int(minutes or 60), RETENTION_H * 60))
    since = int(time.time()) - mins * 60
    with db() as c:
        rows = c.execute(
            "SELECT ts, sai, fw_drop_rate, ssh_failed_1h, ssh_invalid_1h, f2b_banned "
            "FROM metrics WHERE host=? AND ts>=? ORDER BY ts", (host, since)).fetchall()
    if mins <= 60:
        bucket = 0       # raw
    elif mins <= 360:
        bucket = 60
    elif mins <= 1440:
        bucket = 300
    else:
        bucket = 600
    points = []
    if bucket == 0:
        for r in rows:
            points.append({"ts": r["ts"], "sai": r["sai"],
                           "fw_rate": r["fw_drop_rate"], "ssh_failed": r["ssh_failed_1h"],
                           "ssh_invalid": r["ssh_invalid_1h"], "f2b_banned": r["f2b_banned"]})
    else:
        # bucket: media dei valori nel bucket, sai = max (picco)
        buckets = {}
        for r in rows:
            b = r["ts"] - (r["ts"] % bucket)
            buckets.setdefault(b, []).append(r)
        for b in sorted(buckets):
            grp = buckets[b]
            def avg(f):
                vals = [g[f] for g in grp if g[f] is not None]
                return round(statistics.mean(vals), 2) if vals else None
            points.append({"ts": b, "sai": max((g["sai"] or 0) for g in grp),
                           "fw_rate": avg("fw_drop_rate"), "ssh_failed": avg("ssh_failed_1h"),
                           "ssh_invalid": avg("ssh_invalid_1h"), "f2b_banned": avg("f2b_banned")})
    return {"host": host, "minutes": mins, "points": points}


def _security_events(host, minutes, limit, event_type):
    """Feed eventi security con filtro per tipo e finestra temporale."""
    mins = max(1, min(int(minutes or 60), SECURITY_RETENTION_H * 60))
    since = int(time.time()) - mins * 60
    lim = max(1, min(int(limit or 200), 1000))
    with db() as c:
        if host:
            q = ("SELECT id,ts,host,event_type,severity,value,baseline,details_json "
                 "FROM security_events WHERE host=? AND ts>=?")
            args = [host, since]
        else:
            q = ("SELECT id,ts,host,event_type,severity,value,baseline,details_json "
                 "FROM security_events WHERE ts>=?")
            args = [since]
        if event_type and event_type != "all":
            q += " AND event_type=?"
            args.append(event_type)
        q += " ORDER BY ts DESC LIMIT ?"
        args.append(lim)
        rows = c.execute(q, args).fetchall()
    return {"events": [{"id": r["id"], "ts": r["ts"], "host": r["host"],
                        "type": r["event_type"], "severity": r["severity"],
                        "value": r["value"], "baseline": r["baseline"],
                        "details": json.loads(r["details_json"] or "{}")} for r in rows]}


def _security_peers(host):
    """Peer di rete storici per host (per il drawer: new/rare/confirmed)."""
    with db() as c:
        rows = c.execute(
            "SELECT direction, ip, port, first_seen, last_seen, max_connections "
            "FROM security_peers WHERE host=? ORDER BY last_seen DESC", (host,)).fetchall()
    now = int(time.time())
    out = []
    for r in rows:
        age = now - r["first_seen"]
        # 'new' = apparso nelle ultime 6h, 'rare' = nelle ultime 24h, altrimenti 'confirmed'
        if age < 21600:
            status = "new"
        elif age < 86400:
            status = "rare"
        else:
            status = "confirmed"
        out.append({"direction": r["direction"], "ip": r["ip"], "port": r["port"],
                    "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                    "max_connections": r["max_connections"], "status": status})
    return {"host": host, "peers": out}


def _security_ports(host):
    """Porte in ascolto storiche + correlazione nmap (listening vs reachable).
    Distingue 'N/A' (scan assente) da '0 CVE' (vulners disattivato) da CVE reali."""
    with db() as c:
        rows = c.execute(
            "SELECT proto, addr, port, first_seen, last_seen "
            "FROM security_ports WHERE host=? ORDER BY port", (host,)).fetchall()
    now = int(time.time())
    # porte raggiungibili dall'ultima scansione nmap
    scan = get_scan(host)
    reachable = {}   # "tcp/443" -> {service, cves, highest_cvss}
    scan_status = "none"
    if scan and scan.get("result"):
        scan_status = scan.get("status", "none")
        for p in (scan["result"].get("ports") or []):
            key = "%s/%d" % (p.get("proto") or "tcp", p.get("port") or 0)
            vulns = p.get("vulns") or []
            reachable[key] = {
                "service": p.get("service"), "product": p.get("product"),
                "version": p.get("version"), "cve_count": len(vulns),
                "highest_cvss": max((v.get("cvss") or 0) for v in vulns) if vulns else None,
                "has_exploit": any(v.get("exploit") for v in vulns),
            }
    out = []
    for r in rows:
        key = "%s/%d" % (r["proto"], r["port"])
        age = now - r["first_seen"]
        is_new = age < 21600
        rc = reachable.get(key)
        out.append({
            "proto": r["proto"], "addr": r["addr"], "port": r["port"],
            "first_seen": r["first_seen"], "last_seen": r["last_seen"],
            "is_new": is_new, "sensitive": r["port"] in SENSITIVE_PORTS,
            "nmap_reachable": rc is not None,
            "nmap_service": rc["service"] if rc else None,
            "nmap_cve_count": rc["cve_count"] if rc else None,
            "nmap_highest_cvss": rc["highest_cvss"] if rc else None,
            "nmap_has_exploit": rc["has_exploit"] if rc else None,
        })
    return {"host": host, "ports": out, "scan_status": scan_status,
            "nmap_enabled": NMAP_ENABLED, "vuln_enabled": NMAP_VULN}


# ---------------------------------------------------------------- web
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # niente rumore su stdout

    def _send(self, code, body, ctype):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj), "application/json")

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def _hosts_list(self):
        return [{"name": n, "target": t} for n, t in HOSTS]

    def _json_cookie(self, code, obj, cookie):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _cookie(self, name):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return None

    def _user(self):
        tok = self._cookie(COOKIE)
        if not tok:
            return None
        un = verify_token(tok)
        if not un:
            return None
        rec = USERS.get(un)
        return {"name": un, "role": rec.get("role"), "status": rec.get("status")} if rec else None

    def _serve_file(self, fname, ctype="text/html; charset=utf-8"):
        try:
            with open(os.path.join(HERE, fname), "rb") as f:
                self._send(200, f.read(), ctype)
        except Exception:
            self._send(500, "%s non trovato" % fname, "text/plain")

    def do_GET(self):
        u = urlparse(self.path)
        # rotte pubbliche (pagina di login / stato auth)
        if u.path == "/login":
            return self._serve_file("login.html")
        if u.path == "/api/authstate":
            return self._json(200, {"users": len(USERS), "needs_setup": len(USERS) == 0})
        # gate: tutto il resto richiede sessione valida
        user = self._user()
        if not user:
            if u.path.startswith("/api/"):
                return self._json(401, {"error": "non autenticato"})
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return
        if u.path == "/api/me":
            return self._json(200, dict(user, version=VERSION, build=BUILD_DATE, author=AUTHOR))
        if u.path == "/api/users":
            if user["role"] != "admin":
                return self._json(403, {"error": "richiede admin"})
            with _users_lock:
                lst = [{"name": n, "role": r.get("role"), "status": r.get("status"),
                        "created": r.get("created")} for n, r in USERS.items()]
            lst.sort(key=lambda x: (x["status"] != "pending", x["name"]))
            return self._json(200, {"users": lst})
        if u.path in ("/", "/index.html"):
            return self._serve_file("dashboard.html")
        if u.path == "/api/latest":
            with _lock:
                payload = {
                    "hosts": [n for n, _ in HOSTS],
                    "interval": INTERVAL,
                    "server_ts": int(time.time()),
                    "data": dict(_latest),
                }
            self._send(200, json.dumps(payload), "application/json")
        elif u.path == "/api/history":
            q = parse_qs(u.query)
            host = (q.get("host") or [""])[0]
            # finestra temporale: 'minutes' ha priorità su 'hours', cap alla retention
            if q.get("minutes"):
                mins = max(1, int(float(q["minutes"][0])))
            else:
                mins = max(1, int(float((q.get("hours") or ["6"])[0]))) * 60
            mins = min(mins, RETENTION_H * 60)
            since = int(time.time()) - mins * 60
            cols = ("ts,mem_used,mem_total,disk_pct,net_rx_rate,net_tx_rate,"
                    "fw_drop_rate,estab,ssh_failed_1h,cont_running,cont_total,"
                    "dock_cpu,dock_mem")

            def fetch(h):
                with db() as c:
                    rows = c.execute(
                        "SELECT %s FROM metrics WHERE host=? AND ts>=? ORDER BY ts" % cols,
                        (h, since)).fetchall()
                data = [dict(r) for r in rows]
                cap = 700  # downsample per non spedire payload enormi
                if len(data) > cap:
                    step = len(data) // cap + 1
                    data = data[::step]
                return data

            if host:  # compat: singolo host -> lista
                self._send(200, json.dumps(fetch(host)), "application/json")
            else:     # tutti gli host -> {host: [righe]}
                out = {n: fetch(n) for n, _ in list(HOSTS)}
                self._send(200, json.dumps(out), "application/json")
        elif u.path == "/api/settings":
            self._json(200, {"nmap_enabled": NMAP_ENABLED, "nmap_vuln": NMAP_VULN,
                             "nmap_deep": NMAP_DEEP, "nmap_top_ports": NMAP_TOP_PORTS,
                             "nmap_interval_hours": NMAP_INTERVAL_H, "report_email": REPORT_EMAIL})
        elif u.path == "/api/scans":
            # riepiloghi per il KPI di sicurezza RAG delle card (tutti gli host)
            now = int(time.time())
            out = {}
            with _scan_lock:
                running = set(_scans_running)
            for name, _t in list(HOSTS):
                cur = get_scan(name)
                if cur:
                    s = scan_summary(cur["result"]) or {}
                    s.update({"ts": cur["ts"], "age": now - cur["ts"],
                              "status": cur["status"], "running": name in running})
                    out[name] = s
                else:
                    out[name] = {"status": "none", "running": name in running}
            self._json(200, {"scans": out, "enabled": NMAP_ENABLED, "vuln": NMAP_VULN})
        elif u.path == "/api/scan":
            q = parse_qs(u.query)
            host = (q.get("host") or [""])[0]
            names = [n for n, _ in HOSTS]
            if not host or host not in names:
                return self._json(404, {"error": "host inesistente"})
            cur = get_scan(host)
            with _scan_lock:
                running = host in _scans_running
            now = int(time.time())
            resp = {"host": host, "running": running, "enabled": NMAP_ENABLED,
                    "interval_hours": NMAP_INTERVAL_H, "deep": NMAP_DEEP,
                    "top_ports": NMAP_TOP_PORTS, "vuln": NMAP_VULN}
            if cur:
                resp.update({"ts": cur["ts"], "age": now - cur["ts"],
                             "duration": cur["duration"], "status": cur["status"],
                             "result": cur["result"]})
                resp["remediation"] = build_remediation(cur["result"])
            else:
                resp["status"] = "none"
            self._json(200, resp)
        elif u.path == "/api/hosts":
            self._json(200, {"hosts": self._hosts_list()})
        elif u.path == "/api/setup":
            # info per abilitare un nuovo server: chiave pubblica + riga authorized_keys
            pub = read_pubkey()
            line = ('command="%s",no-agent-forwarding,no-port-forwarding,'
                    'no-pty,no-user-rc,no-X11-forwarding %s' % (FORCED_CMD, pub or "<pubkey>"))
            self._json(200, {
                "pubkey": pub,
                "probe_path": FORCED_CMD,
                "authorized_keys_line": line,
                "note": ("Sul nuovo server: installa la sonda in %s (755) e aggiungi la riga "
                         "sopra a ~/.ssh/authorized_keys dell'utente indicato nel target." % FORCED_CMD),
            })
        elif u.path == "/api/security/overview":
            self._json(200, _security_overview())
        elif u.path == "/api/security/history":
            q = parse_qs(u.query)
            host = (q.get("host") or [""])[0]
            mins = (q.get("minutes") or ["60"])[0]
            if not host or host not in [n for n, _ in HOSTS]:
                return self._json(404, {"error": "host inesistente"})
            self._json(200, _security_history(host, mins))
        elif u.path == "/api/security/events":
            q = parse_qs(u.query)
            host = (q.get("host") or [""])[0]
            mins = (q.get("minutes") or ["60"])[0]
            lim = (q.get("limit") or ["200"])[0]
            etype = (q.get("type") or ["all"])[0]
            self._json(200, _security_events(host, mins, lim, etype))
        elif u.path == "/api/security/peers":
            q = parse_qs(u.query)
            host = (q.get("host") or [""])[0]
            if not host or host not in [n for n, _ in HOSTS]:
                return self._json(404, {"error": "host inesistente"})
            self._json(200, _security_peers(host))
        elif u.path == "/api/security/ports":
            q = parse_qs(u.query)
            host = (q.get("host") or [""])[0]
            if not host or host not in [n for n, _ in HOSTS]:
                return self._json(404, {"error": "host inesistente"})
            self._json(200, _security_ports(host))
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        u = urlparse(self.path)
        # --- rotte pubbliche di autenticazione ---
        if u.path == "/api/register":
            b = self._read_json()
            un = (b.get("username") or "").strip()
            pw = b.get("password") or ""
            if not USER_RE.match(un):
                return self._json(400, {"error": "username non valido (3-32: lettere, cifre, . _ -)"})
            if len(pw) < 8:
                return self._json(400, {"error": "la password deve avere almeno 8 caratteri"})
            with _users_lock:
                if un in USERS:
                    return self._json(400, {"error": "utente già esistente"})
                first = len(USERS) == 0
                make_user(un, pw, "admin" if first else "user", "active" if first else "pending")
                save_users()
            if first:
                return self._json_cookie(200, {"ok": True, "role": "admin", "status": "active"},
                                         cookie_str(make_token(un)))
            return self._json(200, {"ok": True, "status": "pending",
                                    "note": "registrazione ricevuta: in attesa di approvazione di un amministratore"})
        if u.path == "/api/login":
            b = self._read_json()
            un = (b.get("username") or "").strip()
            pw = b.get("password") or ""
            with _users_lock:
                rec = USERS.get(un)
            if not rec or not check_pw(rec, pw):
                return self._json(401, {"error": "credenziali non valide"})
            if rec.get("status") != "active":
                return self._json(403, {"error": "account in attesa di approvazione"})
            return self._json_cookie(200, {"ok": True, "role": rec.get("role")},
                                     cookie_str(make_token(un)))

        # --- gate: il resto richiede sessione ---
        user = self._user()
        if not user:
            return self._json(401, {"error": "non autenticato"})

        if u.path == "/api/logout":
            return self._json_cookie(200, {"ok": True}, cookie_str("", 0))

        if u.path == "/api/users/create":
            if user["role"] != "admin":
                return self._json(403, {"error": "richiede admin"})
            b = self._read_json()
            un = (b.get("username") or "").strip()
            pw = b.get("password") or ""
            role = (b.get("role") or "user").strip()
            if not USER_RE.match(un):
                return self._json(400, {"error": "username non valido (3-32: lettere, cifre, . _ -)"})
            if len(pw) < 8:
                return self._json(400, {"error": "la password deve avere almeno 8 caratteri"})
            if role not in ("admin", "user"):
                return self._json(400, {"error": "ruolo non valido"})
            with _users_lock:
                if un in USERS:
                    return self._json(400, {"error": "utente già esistente"})
                make_user(un, pw, role, "active")   # creato da admin → subito attivo
                save_users()
            return self._json(200, {"ok": True})

        if u.path == "/api/users/password":
            if user["role"] != "admin":
                return self._json(403, {"error": "richiede admin"})
            b = self._read_json()
            un = (b.get("username") or "").strip()
            pw = b.get("password") or ""
            if len(pw) < 8:
                return self._json(400, {"error": "la password deve avere almeno 8 caratteri"})
            with _users_lock:
                rec = USERS.get(un)
                if not rec:
                    return self._json(404, {"error": "utente inesistente"})
                salt = secrets.token_hex(16)      # rigenero salt+hash (le vecchie sessioni restano valide)
                rec["salt"] = salt
                rec["hash"] = hash_pw(pw, salt)
                save_users()
            return self._json(200, {"ok": True})

        if u.path in ("/api/users/approve", "/api/users/reject",
                      "/api/users/delete", "/api/users/role"):
            if user["role"] != "admin":
                return self._json(403, {"error": "richiede admin"})
            b = self._read_json()
            un = (b.get("username") or "").strip()
            with _users_lock:
                rec = USERS.get(un)
                if not rec:
                    return self._json(404, {"error": "utente inesistente"})
                # numero di admin attivi (per non lasciare il sistema senza amministratori)
                active_admins = sum(1 for r in USERS.values()
                                    if r.get("role") == "admin" and r.get("status") == "active")

                if u.path.endswith("approve"):
                    rec["status"] = "active"

                elif u.path.endswith("reject"):
                    if rec.get("status") == "active":
                        return self._json(400, {"error": "utente già attivo: usa Elimina"})
                    USERS.pop(un, None)

                elif u.path.endswith("delete"):
                    if un == user["name"]:
                        return self._json(400, {"error": "non puoi eliminare te stesso"})
                    if rec.get("role") == "admin" and rec.get("status") == "active" and active_admins <= 1:
                        return self._json(400, {"error": "è l'ultimo amministratore attivo"})
                    USERS.pop(un, None)

                else:  # /api/users/role  (promuovi/declassa admin<->user)
                    new_role = (b.get("role") or "").strip()
                    if new_role not in ("admin", "user"):
                        return self._json(400, {"error": "ruolo non valido"})
                    if (rec.get("role") == "admin" and new_role == "user"
                            and rec.get("status") == "active" and active_admins <= 1):
                        return self._json(400, {"error": "è l'ultimo amministratore attivo"})
                    rec["role"] = new_role
                    if new_role == "admin":     # un admin è per forza attivo
                        rec["status"] = "active"

                save_users()
            return self._json(200, {"ok": True})

        global HOSTS
        if u.path == "/api/hosts":
            b = self._read_json()
            name = (b.get("name") or "").strip()
            target = (b.get("target") or "").strip()
            if not NAME_RE.match(name):
                return self._json(400, {"error": "nome non valido (1-32 caratteri: lettere, cifre, spazio, . _ -)"})
            if not TARGET_RE.match(target):
                return self._json(400, {"error": "target non valido: usa utente@host (es. root@100.0.0.1)"})
            with _lock:
                HOSTS = [(n, t) for n, t in HOSTS if n != name] + [(name, target)]
                save_hosts()
            return self._json(200, {"ok": True, "hosts": self._hosts_list()})

        if u.path == "/api/settings":
            global NMAP_VULN, REPORT_EMAIL
            if user["role"] != "admin":
                return self._json(403, {"error": "richiede admin"})
            b = self._read_json()
            if "nmap_vuln" in b:
                NMAP_VULN = bool(b.get("nmap_vuln"))
                set_setting("nmap_vuln", "1" if NMAP_VULN else "0")
            if "report_email" in b:
                em = (b.get("report_email") or "").strip()
                if not em or "@" not in em or " " in em:
                    return self._json(400, {"error": "email non valida"})
                REPORT_EMAIL = em
                set_setting("report_email", em)
            return self._json(200, {"ok": True, "nmap_vuln": NMAP_VULN, "report_email": REPORT_EMAIL})

        if u.path == "/api/scan":
            if user["role"] != "admin":
                return self._json(403, {"error": "richiede admin"})
            if not NMAP_ENABLED:
                return self._json(400, {"error": "scansione nmap disabilitata"})
            b = self._read_json()
            host = (b.get("host") or "").strip()
            target = dict(HOSTS).get(host)
            if not target:
                return self._json(404, {"error": "host inesistente"})
            with _scan_lock:
                if host in _scans_running:
                    return self._json(200, {"ok": True, "running": True,
                                            "note": "scansione già in corso"})
            scan_async(host, target)   # parte in background; il client fa polling su GET /api/scan
            return self._json(200, {"ok": True, "running": True})

        if u.path == "/api/enroll":
            if user["role"] != "admin":
                return self._json(403, {"error": "richiede admin"})
            b = self._read_json()
            name = (b.get("name") or "").strip()
            target = (b.get("target") or "").strip()
            password = b.get("password") or ""   # usata una sola volta, MAI persistita
            if not NAME_RE.match(name):
                return self._json(400, {"error": "nome non valido"})
            if not TARGET_RE.match(target):
                return self._json(400, {"error": "target non valido: usa utente@host"})
            if not password:
                return self._json(400, {"error": "serve la password di bootstrap (usata una volta, mai salvata)"})
            ok, msg = enroll_server(target, password)
            password = None  # scarto subito la credenziale
            if not ok:
                return self._json(400, {"error": msg})
            with _lock:
                HOSTS = [(n, t) for n, t in HOSTS if n != name] + [(name, target)]
                save_hosts()
            return self._json(200, {"ok": True, "message": msg, "hosts": self._hosts_list()})

        self._send(404, "not found", "text/plain")

    def do_DELETE(self):
        u = urlparse(self.path)
        if not self._user():
            return self._json(401, {"error": "non autenticato"})
        if u.path == "/api/hosts":
            name = (parse_qs(u.query).get("name") or [""])[0]
            global HOSTS
            with _lock:
                HOSTS = [(n, t) for n, t in HOSTS if n != name]
                _latest.pop(name, None)
                _prev.pop(name, None)
                save_hosts()
            return self._json(200, {"ok": True, "hosts": self._hosts_list()})
        self._send(404, "not found", "text/plain")


def main():
    init_db()
    load_hosts()
    load_users()
    load_settings()
    t = threading.Thread(target=poller_loop, daemon=True)
    t.start()
    if NMAP_ENABLED:
        threading.Thread(target=scan_loop, daemon=True).start()
    srv = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    print("gp-monitor in ascolto su http://%s:%d — hosts=%s interval=%ds retention=%dh"
          % (BIND_HOST, BIND_PORT, ",".join(n for n, _ in HOSTS), INTERVAL, RETENTION_H), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
