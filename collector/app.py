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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ---------------------------------------------------------------- versione
VERSION = "v2.4"
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
    t = threading.Thread(target=poller_loop, daemon=True)
    t.start()
    srv = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    print("gp-monitor in ascolto su http://%s:%d — hosts=%s interval=%ds retention=%dh"
          % (BIND_HOST, BIND_PORT, ",".join(n for n, _ in HOSTS), INTERVAL, RETENTION_H), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
