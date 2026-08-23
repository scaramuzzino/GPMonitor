#!/usr/bin/env python3
"""Watchdog di allarme per gp-monitor.

Controlla i dati di gp-monitor (SQLite) e, se un server ha un PROBLEMA GRAVE,
invia un'email di WARNING e (se disponibile) lancia il report completo.
Anti-spam: cooldown per-problema, si riarma quando il problema rientra.
Pensato per cron a intervalli brevi (es. */10 * * * *). Uso: watchdog.py [--test]

Configurazione via env (oltre a quelle SMTP di email-report.py, condivise):

  GPMON_DB                  percorso DB            (default ./data/metrics.db)
  GPMON_REPORT_EMAIL        destinatario di fallback (preferito: kv.report_email)
  GPMON_WATCHDOG_STATE      file di stato anti-spam (default ./data/watchdog_state.json)
  GPMON_REPORT_SCRIPT       script report da lanciare (default: email-report.py affiancato)
  GPMON_WD_COOLDOWN         secondi di cooldown per stesso problema (default 7200)
  GPMON_WD_DISK_CRIT        soglia disco %% critica    (default 90)
  GPMON_WD_MEM_CRIT         soglia RAM %% critica       (default 95)
  GPMON_WD_STALE            secondi oltre cui l'host e' "irraggiungibile" (default 300)
  GPMON_WD_SSH_REAL         SSH falliti/h che raggiungono sshd = allarme (default 10)

  SMTP: GPMON_SMTP_HOST/PORT/SSL/FROM/USER/PASSWORD[_FILE]/INSECURE (vedi email-report.py)

Autore: Stefano Scaramuzzino
"""
import sqlite3, json, ssl, smtplib, time, os, sys, subprocess, html
from datetime import datetime
from email.message import EmailMessage


def _env(k, d=None):
    return os.environ.get(k, d)


HERE = os.path.dirname(os.path.abspath(__file__))
DB = _env("GPMON_DB", "./data/metrics.db")
STATE = _env("GPMON_WATCHDOG_STATE", "./data/watchdog_state.json")
REPORT = _env("GPMON_REPORT_SCRIPT", os.path.join(HERE, "email-report.py"))
COOLDOWN = int(_env("GPMON_WD_COOLDOWN", "7200"))
DISK_CRIT = int(_env("GPMON_WD_DISK_CRIT", "90"))
MEM_CRIT = int(_env("GPMON_WD_MEM_CRIT", "95"))
STALE = int(_env("GPMON_WD_STALE", "300"))
SSH_REAL = int(_env("GPMON_WD_SSH_REAL", "10"))

SMTP_HOST = _env("GPMON_SMTP_HOST", "localhost")
SMTP_PORT = int(_env("GPMON_SMTP_PORT", "465"))
SMTP_SSL = _env("GPMON_SMTP_SSL", "1") == "1"
SMTP_FROM = _env("GPMON_SMTP_FROM", "gpmonitor@localhost")
SMTP_USER = _env("GPMON_SMTP_USER", SMTP_FROM)
SMTP_INSECURE = _env("GPMON_SMTP_INSECURE", "0") == "1"

RED, AMBER, INK = "#c62828", "#ed6c02", "#1b2430"


def esc(s):
    return html.escape(str(s))


def smtp_password():
    p = _env("GPMON_SMTP_PASSWORD")
    if p:
        return p
    pf = _env("GPMON_SMTP_PASSWORD_FILE")
    if pf:
        with open(pf) as f:
            return f.read().strip()
    return ""


def recipient():
    try:
        c = sqlite3.connect(DB, timeout=10)
        r = c.execute("select v from kv where k='report_email'").fetchone()
        if r and r[0]:
            return r[0]
    except Exception:
        pass
    return _env("GPMON_REPORT_EMAIL", "")


def send(subject, html_body, text_body):
    to = recipient()
    if not to:
        raise SystemExit("Nessun destinatario: impostalo in dashboard (Config) o via GPMON_REPORT_EMAIL")
    m = EmailMessage(); m["From"] = SMTP_FROM; m["To"] = to; m["Subject"] = subject
    m.set_content(text_body); m.add_alternative(html_body, subtype="html")
    ctx = ssl.create_default_context()
    if SMTP_INSECURE:
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    pw = smtp_password()
    if SMTP_SSL:
        s = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx, timeout=30)
    else:
        s = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30); s.starttls(context=ctx)
    if pw:
        s.login(SMTP_USER, pw)
    s.send_message(m); s.quit()


def load_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(st):
    try:
        os.makedirs(os.path.dirname(STATE) or ".", exist_ok=True)
        with open(STATE, "w") as f:
            json.dump(st, f)
    except Exception:
        pass


def problems():
    c = sqlite3.connect(DB, timeout=15); c.row_factory = sqlite3.Row
    hosts = [r["name"] for r in c.execute("select name from hosts order by name")] \
        or [r[0] for r in c.execute("select distinct host from metrics")]
    now = int(time.time()); out = []
    for h in hosts:
        m = c.execute("select * from metrics where host=? order by ts desc limit 1", (h,)).fetchone()
        if not m:
            out.append((h, "no-data", "Nessuna metrica dal collector", ""))
            continue
        if now - m["ts"] > STALE:
            out.append((h, "stale", "Irraggiungibile da gp-monitor", f"ultimo dato {int((now - m['ts']) / 60)} min fa"))
            continue
        if (m["disk_pct"] or 0) >= DISK_CRIT:
            out.append((h, "disk", "Disco quasi pieno", f"{m['disk_pct']:.0f}%"))
        memp = (m["mem_used"] / m["mem_total"] * 100) if m["mem_total"] else 0
        if memp >= MEM_CRIT:
            out.append((h, "mem", "RAM quasi esaurita", f"{memp:.0f}%"))
        if (m["ssh_failed_1h"] or 0) >= SSH_REAL:
            out.append((h, "ssh", "SSH: tentativi che RAGGIUNGONO sshd (possibile attacco reale)",
                        f"{m['ssh_failed_1h']} in 1h"))
    return out


def render(probs, test=False):
    rows = ""
    for h, k, desc, val in probs:
        rows += (f'<tr><td style="padding:7px 10px;border-bottom:1px solid #eee;font-family:Arial;font-size:13px">'
                 f'<b>{esc(h)}</b></td>'
                 f'<td style="padding:7px 10px;border-bottom:1px solid #eee;font-family:Arial;font-size:13px">'
                 f'<span style="background:{RED};color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;'
                 f'font-weight:bold">GRAVE</span> {esc(desc)}</td>'
                 f'<td style="padding:7px 10px;border-bottom:1px solid #eee;font-family:Arial;font-size:13px;'
                 f'color:{RED};font-weight:bold">{esc(val)}</td></tr>')
    banner = "ESEMPIO (test) — nessun problema reale" if test else "PROBLEMI GRAVI rilevati"
    h = (f'<div style="font-family:Arial;max-width:720px;margin:0 auto">'
         f'<div style="background:{RED};color:#fff;padding:14px 18px;border-radius:8px 8px 0 0;font-size:17px;'
         f'font-weight:bold">⚠ {banner}</div>'
         f'<div style="border:1px solid #eee;border-top:0;border-radius:0 0 8px 8px;padding:14px 16px">'
         f'<div style="font-size:12px;color:{INK};margin-bottom:8px">{datetime.now().strftime("%d/%m/%Y %H:%M")} '
         f'&middot; watchdog gp-monitor</div>'
         f'<table style="width:100%;border-collapse:collapse"><tr>'
         f'<th style="text-align:left;padding:7px 10px;background:{INK};color:#fff;font-family:Arial;font-size:12px">Server</th>'
         f'<th style="text-align:left;padding:7px 10px;background:{INK};color:#fff;font-family:Arial;font-size:12px">Problema</th>'
         f'<th style="text-align:left;padding:7px 10px;background:{INK};color:#fff;font-family:Arial;font-size:12px">Valore</th>'
         f'</tr>{rows}</table>'
         f'<div style="font-size:12px;color:{INK};margin-top:10px">A seguire arriva anche il <b>report completo</b>.</div>'
         f'</div></div>')
    t = "ALERT watchdog:\n" + "\n".join(f"- {h_}: {desc} ({val})" for h_, k, desc, val in probs)
    return h, t


def run_report():
    if REPORT and os.path.exists(REPORT):
        try:
            subprocess.run([sys.executable, REPORT], timeout=120)
        except Exception:
            pass


def main():
    test = "--test" in sys.argv
    if test:
        probs = [("srv-01", "demo", "Esempio di avviso (disco/RAM/irraggiungibile/attacco SSH reale)", "test")]
        hb, tb = render(probs, test=True)
        send("[gp-monitor ALERT] TEST watchdog — esempio di avviso", hb, tb)
        run_report()
        print("test alert + report inviati"); return

    probs = problems()
    st = load_state(); now = int(time.time())
    keys_now = {f"{h}:{k}" for h, k, _, _ in probs}
    to_alert = [p for p in probs if (now - st.get(f"{p[0]}:{p[1]}", 0)) > COOLDOWN]
    st = {kk: v for kk, v in st.items() if kk in keys_now}  # scorda i problemi risolti
    if to_alert:
        hb, tb = render(to_alert)
        send(f"[gp-monitor ALERT] problemi gravi: {', '.join(sorted({p[0] for p in to_alert}))}", hb, tb)
        run_report()
        for p in to_alert:
            st[f"{p[0]}:{p[1]}"] = now
        print("ALERT inviato per:", to_alert)
    else:
        print("nessun problema grave (o in cooldown).")
    save_state(st)


if __name__ == "__main__":
    main()
