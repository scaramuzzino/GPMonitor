#!/usr/bin/env python3
"""Report giornaliero via email dello stato della flotta gp-monitor.

Legge il DB SQLite di gp-monitor e invia un'email HTML (tabelle, badge RAG,
grafici a barre CSS — Gmail-safe: niente SVG/JS/immagini esterne) con: salute
(disco/RAM/Docker), vulnerabilita' CVE per host, analisi attacchi (minaccia
reale vs rumore bloccato) e utenze della dashboard. NON invia MAI password.

Tutto configurabile via variabili d'ambiente (nessun valore hardcoded):

  GPMON_DB                  percorso DB           (default ./data/metrics.db)
  GPMON_REPORT_EMAIL        destinatario di fallback se non impostato in dashboard
  GPMON_SMTP_HOST           host SMTP            (default localhost)
  GPMON_SMTP_PORT           porta SMTP           (default 465)
  GPMON_SMTP_SSL            1=SMTP_SSL (default), 0=SMTP+STARTTLS
  GPMON_SMTP_FROM           mittente             (default gpmonitor@localhost)
  GPMON_SMTP_USER           utente login SMTP    (default = FROM)
  GPMON_SMTP_PASSWORD       password SMTP        (oppure GPMON_SMTP_PASSWORD_FILE)
  GPMON_SMTP_PASSWORD_FILE  file con la password
  GPMON_SMTP_INSECURE       1 = non verificare il certificato TLS (self-signed)

Il destinatario preferito e' quello impostato dalla dashboard (kv.report_email);
in mancanza usa GPMON_REPORT_EMAIL. Pensato per cron (es. 0 8 * * *).

Autore: Stefano Scaramuzzino
"""
import sqlite3, json, ssl, smtplib, time, os, html
from datetime import datetime
from email.message import EmailMessage


def _env(k, d=None):
    return os.environ.get(k, d)


DB = _env("GPMON_DB", "./data/metrics.db")
SMTP_HOST = _env("GPMON_SMTP_HOST", "localhost")
SMTP_PORT = int(_env("GPMON_SMTP_PORT", "465"))
SMTP_SSL = _env("GPMON_SMTP_SSL", "1") == "1"
SMTP_FROM = _env("GPMON_SMTP_FROM", "gpmonitor@localhost")
SMTP_USER = _env("GPMON_SMTP_USER", SMTP_FROM)
SMTP_INSECURE = _env("GPMON_SMTP_INSECURE", "0") == "1"

GREEN, AMBER, RED, GREY, BLUE, INK = "#2e7d32", "#ed6c02", "#c62828", "#607d8b", "#1565c0", "#1b2430"


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
    """Preferisci il destinatario impostato in dashboard (kv.report_email),
    altrimenti GPMON_REPORT_EMAIL."""
    try:
        c = sqlite3.connect(DB, timeout=10)
        r = c.execute("select v from kv where k='report_email'").fetchone()
        if r and r[0]:
            return r[0]
    except Exception:
        pass
    return _env("GPMON_REPORT_EMAIL", "")


def esc(s):
    return html.escape(str(s))


def badge(txt, color):
    return (f'<span style="display:inline-block;padding:2px 9px;border-radius:11px;background:{color};'
            f'color:#fff;font-size:11px;font-weight:bold;font-family:Arial">{esc(txt)}</span>')


def bar(pct, color, w=170, label=""):
    pct = max(0, min(100, pct))
    return (f'<table role="presentation" cellpadding="0" cellspacing="0" style="width:{w}px;'
            f'border-collapse:separate;background:#e9edf1;border-radius:5px;display:inline-table;vertical-align:middle">'
            f'<tr><td style="width:{pct:.0f}%;background:{color};height:14px;border-radius:5px;font-size:0;line-height:0">&nbsp;</td>'
            f'<td style="height:14px;font-size:0;line-height:0">&nbsp;</td></tr></table>'
            + (f' <span style="font-size:12px;color:{INK};font-family:Arial">{esc(label)}</span>' if label else ""))


def stacked(segs, total_w=180):
    cells = ""
    for p, c in segs:
        if p <= 0:
            continue
        cells += f'<td style="width:{p:.1f}%;background:{c};height:14px;font-size:0;line-height:0">&nbsp;</td>'
    cells += '<td style="height:14px;font-size:0;line-height:0">&nbsp;</td>'
    return (f'<table role="presentation" cellpadding="0" cellspacing="0" style="width:{total_w}px;'
            f'border-collapse:separate;background:#e9edf1;border-radius:5px;display:inline-table;vertical-align:middle"><tr>{cells}</tr></table>')


def disk_col(p):
    return GREEN if p < 70 else AMBER if p < 85 else RED


def sec_rag(cs):
    if cs is None:
        return ("n/d", GREY)
    if cs["expl"] > 0 or cs["crit"] > 0:
        return ("ROSSO", RED)
    if cs["tot"] > 0:
        return ("AMBRA", AMBER)
    return ("VERDE", GREEN)


def cve_summary(j):
    try:
        d = json.loads(j)
    except Exception:
        return None
    best = {}
    for p in (d.get("ports") or []):
        for v in (p.get("vulns") or []):
            vid = v.get("id"); cv = v.get("cvss") or 0
            if vid is None:
                continue
            if vid not in best or cv > best[vid][0]:
                best[vid] = (cv, bool(v.get("exploit")))
    tot = len(best); crit = sum(1 for c, _ in best.values() if c >= 9)
    high = sum(1 for c, _ in best.values() if 7 <= c < 9); expl = sum(1 for _, e in best.values() if e)
    top = sorted(best.items(), key=lambda kv: (-kv[1][0], not kv[1][1]))[:6]
    os_ = d.get("os") or []
    osname = (os_[0]["name"] + f" ({os_[0].get('accuracy')}%)") if os_ else "n/d"
    openp = []
    for p in (d.get("ports") or []):
        if p.get("state") != "open":
            continue
        svc = " ".join(x for x in [p.get("service"), p.get("product"), p.get("version")] if x)
        openp.append((f"{p.get('port')}/{p.get('proto')}", svc or "-"))
    return dict(tot=tot, crit=crit, high=high, expl=expl, top=top, os=osname, openp=openp, ports=len(openp))


def th(t):
    return (f'<th style="text-align:left;padding:7px 10px;background:{INK};color:#fff;'
            f'font-family:Arial;font-size:12px;font-weight:bold">{t}</th>')


def td(t, extra=""):
    return (f'<td style="padding:7px 10px;border-bottom:1px solid #e3e8ee;font-family:Arial;'
            f'font-size:13px;color:{INK};{extra}">{t}</td>')


def build():
    c = sqlite3.connect(DB, timeout=15); c.row_factory = sqlite3.Row
    hosts = [r["name"] for r in c.execute("select name from hosts order by name")] \
        or [r[0] for r in c.execute("select distinct host from metrics")]
    now = int(time.time()); since = now - 86400
    data = []
    for h in hosts:
        m = c.execute("select * from metrics where host=? order by ts desc limit 1", (h,)).fetchone()
        agg = c.execute("select max(f2b_banned) fb,max(ssh_failed_1h) sf,max(fw_drop_rate) fw,"
                        "sum(ssh_failed_1h) sfs,count(*) n from metrics where host=? and ts>=?",
                        (h, since)).fetchone()
        sc = c.execute("select json,ts from scans where host=? order by ts desc limit 1", (h,)).fetchone()
        cs = cve_summary(sc["json"]) if sc and sc["json"] else None
        data.append(dict(h=h, m=m, agg=agg, sc=sc, cs=cs, fresh=bool(m and now - m["ts"] < 300)))
    maxcve = max([d["cs"]["tot"] for d in data if d["cs"]] or [1]) or 1
    maxfw = max([(d["agg"]["fw"] or 0) for d in data] or [1]) or 1

    P = []
    P.append(f'<div style="font-family:Arial,sans-serif;max-width:820px;margin:0 auto;color:{INK}">')
    P.append(f'<div style="background:{INK};color:#fff;padding:16px 20px;border-radius:8px 8px 0 0">'
             f'<div style="font-size:19px;font-weight:bold">Stato server &middot; flotta gp-monitor</div>'
             f'<div style="font-size:12px;opacity:.8">{datetime.now().strftime("%A %d/%m/%Y &middot; %H:%M")} '
             f'&middot; fonte: gp-monitor (agentless)</div></div>')
    P.append('<div style="border:1px solid #e3e8ee;border-top:0;border-radius:0 0 8px 8px;padding:16px 18px">')

    # ---- Riepilogo con RAG + barre
    P.append('<div style="font-size:14px;font-weight:bold;margin:2px 0 8px">Riepilogo</div>')
    P.append('<table style="width:100%;border-collapse:collapse;margin-bottom:6px"><tr>'
             + th("Server") + th("Stato") + th("Disco") + th("RAM") + th("Docker")
             + th("Sicurezza") + th("CVE (crit/expl)") + '</tr>')
    for i, d in enumerate(data):
        m = d["m"]; bg = "#ffffff" if i % 2 == 0 else "#f6f8fa"
        st = badge("ONLINE", GREEN) if d["fresh"] else badge("OFFLINE", RED)
        if m:
            dp = m["disk_pct"] or 0; rp = (m["mem_used"] / m["mem_total"] * 100) if m["mem_total"] else 0
            disk = bar(dp, disk_col(dp), 120, f"{dp:.0f}%"); ram = bar(rp, disk_col(rp), 120, f"{rp:.0f}%")
            dock = f'{m["cont_running"]}/{m["cont_total"]}'
        else:
            disk = ram = "n/d"; dock = "n/d"
        lab, col = sec_rag(d["cs"]); sec = badge(lab, col)
        cve = (f'{d["cs"]["crit"]} / {d["cs"]["expl"]}' if d["cs"] else "n/d")
        P.append(f'<tr style="background:{bg}">' + td(f'<b>{esc(d["h"])}</b>') + td(st) + td(disk)
                 + td(ram) + td(dock) + td(sec) + td(cve) + '</tr>')
    P.append('</table>')
    P.append(f'<div style="font-size:11px;color:{GREY};margin-bottom:14px">Legenda: {badge("VERDE", GREEN)} ok '
             f'&nbsp; {badge("AMBRA", AMBER)} da rivedere &nbsp; {badge("ROSSO", RED)} critico. '
             f'Le password NON sono incluse (sicurezza).</div>')

    # ---- CVE per server (barra impilata: critiche/gravi/altre)
    P.append('<div style="font-size:14px;font-weight:bold;margin:14px 0 8px">Vulnerabilita&#39; per server (CVE)</div>')
    P.append('<table style="width:100%;border-collapse:collapse"><tr>' + th("Server") + th("Grafico (scala sul max)")
             + th("Totale") + th("Critiche") + th("Gravi") + th("Exploit") + '</tr>')
    for i, d in enumerate(data):
        bg = "#ffffff" if i % 2 == 0 else "#f6f8fa"; cs = d["cs"]
        if cs and cs["tot"]:
            scale = cs["tot"] / maxcve * 100.0

            def seg(n, cs=cs, scale=scale):
                return (n / cs["tot"] * scale) if cs["tot"] else 0
            other = cs["tot"] - cs["crit"] - cs["high"]
            g = stacked([(seg(cs["crit"]), RED), (seg(cs["high"]), AMBER), (seg(other), GREY)], 200)
            row = (td(f'<b>{esc(d["h"])}</b>') + td(g) + td(str(cs["tot"]))
                   + td(badge(str(cs["crit"]), RED) if cs["crit"] else "0")
                   + td(badge(str(cs["high"]), AMBER) if cs["high"] else "0")
                   + td(badge(f'⚡{cs["expl"]}', RED) if cs["expl"] else "0"))
        else:
            row = td(f'<b>{esc(d["h"])}</b>') + td("nessuna scansione") + td("-") + td("-") + td("-") + td("-")
        P.append(f'<tr style="background:{bg}">' + row + '</tr>')
    P.append('</table>')
    P.append(f'<div style="font-size:11px;color:{GREY};margin:4px 0 14px">Rosso=critiche (CVSS&ge;9) '
             f'&middot; Ambra=gravi (7-9) &middot; Grigio=altre. Le CVE correlate sulla versione upstream '
             f'possono includere falsi positivi (backport della distro).</div>')

    # ---- Attacchi (24h): minaccia reale vs rumore bloccato
    P.append('<div style="font-size:14px;font-weight:bold;margin:14px 0 8px">Attacchi (24h) '
             '&middot; minaccia reale vs rumore bloccato</div>')
    P.append('<table style="width:100%;border-collapse:collapse"><tr>'
             + th("Server") + th("SSH arrivati a sshd") + th("Scan bloccati (rumore)")
             + th("IP bannati (f2b)") + th("Intensita&#39; scan") + th("Verdetto") + '</tr>')
    for i, d in enumerate(data):
        bg = "#ffffff" if i % 2 == 0 else "#f6f8fa"; a = d["agg"]
        fb = a["fb"] or 0; sf = a["sf"] or 0; fw = a["fw"] or 0
        ssh_cell = badge("0 ✓", GREEN) if sf == 0 else badge(str(sf), RED if sf >= 10 else AMBER)
        ratio = (fw / maxfw) if maxfw else 0
        inten = bar(ratio * 100, RED if ratio > 0.66 else AMBER if ratio > 0.33 else GREEN, 150)
        verdict = badge("DIFESO", GREEN) if sf == 0 else badge("DA VERIFICARE", AMBER if sf < 10 else RED)
        P.append(f'<tr style="background:{bg}">' + td(f'<b>{esc(d["h"])}</b>') + td(ssh_cell)
                 + td(f"{fw:.0f}/min") + td(badge(str(fb), BLUE) if fb else "0") + td(inten) + td(verdict) + '</tr>')
    P.append('</table>')
    P.append(f'<div style="font-size:11px;color:{GREY};margin:4px 0 14px">'
             '<b>SSH arrivati a sshd</b> = tentativi che hanno <i>raggiunto</i> il servizio (minaccia reale); '
             'a 0 = il firewall li ferma prima. <b>Scan bloccati</b> = scansioni droppate <i>prima</i> dei '
             'servizi (rumore di fondo, normale su ogni IP pubblico). <b>IP bannati</b> = scanner aggressivi '
             'messi al bando in automatico da fail2ban (whitelist su rete privata/VPN/Docker/admin).</div>')

    # ---- Dettaglio porte/servizi + top CVE per server
    for d in data:
        cs = d["cs"]
        P.append(f'<div style="font-size:13px;font-weight:bold;margin:14px 0 6px">{esc(d["h"])} &middot; dettaglio</div>')
        if cs:
            P.append(f'<div style="font-size:12px;color:{INK};margin-bottom:6px">OS: <b>{esc(cs["os"])}</b> '
                     f'&middot; porte aperte: <b>{cs["ports"]}</b></div>')
            if cs["openp"]:
                P.append('<table style="width:100%;border-collapse:collapse;margin-bottom:6px"><tr>'
                         + th("Porta") + th("Servizio") + '</tr>')
                for p, svc in cs["openp"][:14]:
                    P.append('<tr>' + td(esc(p)) + td(esc(svc)) + '</tr>')
                P.append('</table>')
            if cs["top"]:
                P.append('<div style="font-size:12px;margin:4px 0 2px">Top CVE:</div><div>')
                for vid, (cv, e) in cs["top"]:
                    col = RED if cv >= 9 else AMBER if cv >= 7 else GREY
                    P.append(badge(f'{esc(vid)} {cv:.1f}{" ⚡" if e else ""}', col) + " ")
                P.append('</div>')
        else:
            P.append('<div style="font-size:12px;color:#888">nessuna scansione disponibile</div>')

    # ---- Utenze (solo username/ruolo/stato, MAI password)
    P.append('<div style="font-size:14px;font-weight:bold;margin:16px 0 6px">Utenze (solo username, nessuna password)</div>')
    P.append('<table style="width:100%;border-collapse:collapse"><tr>'
             + th("Dashboard gp-monitor") + th("Ruolo") + th("Stato") + '</tr>')
    for u in c.execute("select username,role,status from users order by username"):
        P.append('<tr>' + td(esc(u["username"])) + td(esc(u["role"])) + td(esc(u["status"])) + '</tr>')
    P.append('</table>')

    P.append(f'<div style="font-size:11px;color:{GREY};margin-top:16px;border-top:1px solid #e3e8ee;'
             f'padding-top:8px">Report automatico &middot; gp-monitor (agentless).</div>')
    P.append('</div></div>')
    return "".join(P), data


def text_fallback(data):
    L = ["STATO SERVER — " + datetime.now().strftime("%d/%m/%Y %H:%M")]
    for d in data:
        m = d["m"]; cs = d["cs"]
        L.append(f"\n{d['h']} [{'ONLINE' if d['fresh'] else 'OFFLINE'}]")
        if m:
            L.append(f"  disco {m['disk_pct']:.0f}% · docker {m['cont_running']}/{m['cont_total']}")
        if cs:
            L.append(f"  CVE {cs['tot']} (crit {cs['crit']}, exploit {cs['expl']}) · OS {cs['os']}")
    L.append("\n(versione HTML per il dettaglio; password non incluse)")
    return "\n".join(L)


def send(subject, html_body, text_body):
    to = recipient()
    if not to:
        raise SystemExit("Nessun destinatario: impostalo in dashboard (Config) o via GPMON_REPORT_EMAIL")
    msg = EmailMessage(); msg["From"] = SMTP_FROM; msg["To"] = to; msg["Subject"] = subject
    msg.set_content(text_body); msg.add_alternative(html_body, subtype="html")
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
    s.send_message(msg); s.quit()
    return to


def main():
    body, data = build(); txt = text_fallback(data)
    subject = f"[gp-monitor] Stato server — {datetime.now().strftime('%d/%m %H:%M')}"
    to = send(subject, body, txt)
    print("report HTML inviato a", to, flush=True)


if __name__ == "__main__":
    main()
