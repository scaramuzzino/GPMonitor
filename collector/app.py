#!/usr/bin/env python3
"""
gp-monitor collector + web.
- Interroga i server via SSH (chiave dedicata, comando forzato = sola sonda).
- Calcola i rate dai contatori (rete, pacchetti droppati dal firewall).
- Salva una storia compatta in SQLite con retention limitata.
- Espone /api/latest, /api/history e la dashboard su una porta bindata a Tailscale.
Solo stdlib.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ---------------------------------------------------------------- versione
VERSION = "v2.8"
BUILD_DATE = "2026-08-23"
AUTHOR = "Stefano Scaramuzzino"

# ---------------------------------------------------------------- config
def parse_hosts(spec):
    # "srv1=root@10.0.0.1,srv2=user@10.0.0.2,srv3=root@10.0.0.3"
    hosts = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        name, target = chunk.split("=", 1)
        hosts.append((name.strip(), target.strip()))
    return hosts


ENV_HOSTS = parse_hosts(os.environ.get(
    "MON_HOSTS",
    "srv1=root@10.0.0.1,srv2=user@10.0.0.2,srv3=root@10.0.0.3",
))
BIND = os.environ.get("MON_BIND", "10.0.0.2:8888")
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
    global NMAP_VULN
    with db() as c:
        row = c.execute("SELECT v FROM kv WHERE k='nmap_vuln'").fetchone()
    if row is None:
        set_setting("nmap_vuln", "1" if NMAP_VULN else "0")  # semina dal default env
    else:
        NMAP_VULN = (row["v"] == "1")


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
    r = data["rates"]
    with db() as c:
        c.execute(
            "INSERT INTO metrics (host,ts,mem_used,mem_total,disk_pct,net_rx_rate,"
            "net_tx_rate,fw_drop_rate,estab,ssh_failed_1h,f2b_banned,cont_running,cont_total) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (name, data["ts"], data["ram"]["used"], data["ram"]["total"],
             (root["use_pct"] if root else None),
             r["net_rx_rate"], r["net_tx_rate"], r["fw_drop_rate"],
             (data.get("conns") or {}).get("estab"),
             sec.get("ssh_failed_1h"), sec.get("f2b_banned"),
             running, total),
        )
        cutoff = int(time.time()) - RETENTION_H * 3600
        c.execute("DELETE FROM metrics WHERE ts < ?", (cutoff,))


def _poll_host(name, target):
    try:
        data = ssh_probe(target)
        data = enrich(name, data)
        with _lock:
            _latest[name] = data
        persist(name, data)
    except Exception as e:
        with _lock:
            _latest[name] = {"name": name, "error": str(e), "ts": int(time.time())}


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
        "Riduci la superficie: filtra/chiudi le porte non necessarie esposte oltre Tailscale.",
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
                    "fw_drop_rate,estab,ssh_failed_1h,cont_running,cont_total")

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
                             "nmap_interval_hours": NMAP_INTERVAL_H})
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
            global NMAP_VULN
            if user["role"] != "admin":
                return self._json(403, {"error": "richiede admin"})
            b = self._read_json()
            if "nmap_vuln" in b:
                NMAP_VULN = bool(b.get("nmap_vuln"))
                set_setting("nmap_vuln", "1" if NMAP_VULN else "0")
            return self._json(200, {"ok": True, "nmap_vuln": NMAP_VULN})

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
