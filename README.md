# GPMonitor

<p>
  <img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-blue.svg">
  <img alt="Python stdlib" src="https://img.shields.io/badge/Python-stdlib%20only-green.svg">
  <img alt="Agentless" src="https://img.shields.io/badge/Architecture-agentless-orange.svg">
  <img alt="On-premise" src="https://img.shields.io/badge/Deployment-on--premise-purple.svg">
  <img alt="Docker" src="https://img.shields.io/badge/Container-Docker-2496ED.svg">
  <img alt="No CDN" src="https://img.shields.io/badge/Dependencies-zero%20external-red.svg">
</p>

> **Host Security Observability Platform — agentless, lightweight, on-premise, stdlib-only.**

Sistema di monitoraggio **agentless** e **100% on-premise** per flotte di server Linux (e Mac),
scritto su misura in **solo Python stdlib** (nessun `pip`, nessun CDN, nessuna telemetria/cloud).

Un collector interroga i server via **SSH** — in qualsiasi contesto: **cloud** (VPS/istanze),
**on-premise** in un datacenter/CED, **LAN** o **VPN** — con una chiave dedicata a **comando
forzato** (che può eseguire SOLO la sonda, in sola lettura).
Raccoglie CPU/RAM, disco, rete, connessioni, container Docker, sicurezza (firewall, SSH, fail2ban)
e — via `nmap` — porte, servizi e CVE. Dashboard web con grafici SVG vanilla, **Security Activity
Dashboard** con SAI (Security Activity Index), report email giornalieri, watchdog di allarme e
auto-ban degli scanner.

---

## Caratteristiche

- **Agentless**: nessun demone installato sui target — solo una sonda-script eseguita via SSH a
  comando forzato (read-only). Un OS = una sonda-script (`monitor-probe.py` per Linux,
  `monitor-probe-macos.py` per macOS, `monitor-probe-windows.ps1` per Windows), scelta in base al
  sistema. Tutte emettono lo **stesso schema JSON**. Mai un agente compilato.
- **On-premise / stdlib**: nessuna dipendenza esterna, nessun traffico verso il cloud
  (unica eccezione opzionale e disattivabile: la correlazione CVE via `vulners`, vedi sotto).
- **Dashboard web** (SVG vanilla): card per host (RAM/disco, **throughput di rete realtime** RX/TX
  con colori distinti e **indicatore di trend**), Security Activity Dashboard con SAI e timeline,
  Sankey dei flussi di rete, dashboard Docker per server in stile Grafana, KPI di sicurezza RAG,
  drawer di scansione nmap con CVE e remediation.
- **Guida integrata**: drawer **❓ Guida** in-app con diagrammi SVG che spiega cos'è la SAI, come si
  calcola, la baseline, gli stati, quali controlli/test vengono fatti e la legenda delle card.
- **Security Activity Dashboard**: SAI (Security Activity Index 0–100), stati NORMAL/ELEVATED/
  ACTIVE_ATTACK/UNKNOWN con hysteresis, timeline SAI per server, Security Changes feed
  deduplicato, correlazione listening vs nmap reachable, drawer di drill-down. Tutto
  collector-side, sonda invariata.
- **Sicurezza**: web in ascolto solo su rete fidata, autenticazione (primo utente = admin),
  cookie di sessione firmati HMAC, gestione utenti.
- **Report & Avvisi via email**: report giornaliero HTML (tabelle, badge RAG, grafici a barre) e
  watchdog che avvisa su problemi gravi. Destinatario configurabile dalla dashboard.
- **Auto-ban** degli scanner aggressivi (fail2ban) con whitelist blindata.
- **Backup del database**: script di backup **online** SQLite (coerente anche sotto scrittura) con
  rotazione — `collector/tools/db-backup.py`, adatto a un cron giornaliero.
- **Installazione da git**: `git clone` + `./install.sh` (o `docker compose up -d --build`) —
  semplice e diretto, come qualsiasi progetto Docker.

---

## Architettura

```
                Macchina di monitoraggio (collector)
   ┌──────────────────────────────────────────────────────┐
   │  container gpmon (Docker, network_mode: host)          │
   │   • poller ogni 15s: ssh -> monitor-probe.py  (JSON)   │
   │   • rate calcolati diffando i contatori                │
   │   • SAI engine: baseline + state + event detection     │
   │   • SQLite WAL (retention configurabile, default 48h)  │
   │     + security_events, security_peers, security_ports  │
   │   • nmap (dal container) verso i target                │
   │   • web http://<MON_BIND>:8888  (solo su rete fidata)   │
   └───────────┬───────────────┬───────────────┬────────────┘
        ssh    │        ssh     │        ssh     │
        srv1   │        srv2    │        srv3    │   (comando forzato, read-only)
     /usr/local/bin/monitor-probe.py  ->  stampa un JSON e termina
```

### Flusso del SAI (Security Activity Index)

```
   Sonda (read-only, SSH forced-command)
     │  JSON: {security:{fw_dropped_pkts, ssh_failed_1h, ssh_invalid_1h,
     │         f2b_banned, f2b_total_failed, listening[]}, flows:{in,out,peers}}
     ▼
   Collector — enrich()           delta/rate dai contatori cumulativi
     │  (gestione reset/wrap/None: None ≠ 0)
     ▼
   Collector — persist()          SQLite metrics + nuove colonne security
     │
     ▼
   Collector — security_analyze()  ◄── collector-side intelligence
     │
     ├── _sai_components()   6 componenti 0..100 vs baseline 1h/6h/24h
     ├── _sai_score()        media pesata + clamp 0..100
     │                       ricalibrazione pesi su metriche disponibili (macOS)
     ├── _classify_state()   NORMAL/ELEVATED/ACTIVE_ATTACK/UNKNOWN
     │                       hysteresis (no oscillazioni ogni 15s)
     │                       ACTIVE ATTACK = SAI alto AND rule composita
     ├── _detect_port_changes()  new/removed listen port → security_events
     ├── _detect_peer_anomalies() new inbound/outbound peer → security_events
     ├── _detect_spikes()        firewall/ssh/fail2ban spike → security_events
     └── _emit_event()           deduplicazione via cooldown
     │
     ▼
   API /api/security/*            overview, history, events, peers, ports
     │
     ▼
   Dashboard (SVG vanilla)        KPI bar + timeline SAI + drawer + Changes feed
```

Componenti (cartella `collector/`):

| File | Ruolo |
|---|---|
| `app.py` | Collector + web server (http.server) + API + scheduler nmap + SAI orchestrator. Single-source di versione/build/autore. |
| `sai_engine.py` | SAI engine — funzioni pure (safe_rate, baseline, normalized_ratio, sai_score, classify_state). Testabile senza DB/SSH. |
| `dashboard.html` | Interfaccia web (SVG vanilla, nessun framework). |
| `login.html` | Pagina di login/registrazione. |
| `monitor-probe.py` | Sonda **Linux** (JSON): RAM (`/proc/meminfo`), disco (`findmnt`), rete (`/proc/net/dev`), conn (`ss`), docker (`docker ps/stats`), sicurezza (drop iptables/ip6tables, SSH da journal, fail2ban, porte). |
| `monitor-probe-macos.py` | Sonda **macOS** (stesso schema JSON): `sysctl`/`vm_stat`, `df`, `netstat`. |
| `monitor-probe-windows.ps1` | Sonda **Windows** (PowerShell, stesso schema JSON): `Win32_OperatingSystem`/`Win32_LogicalDisk`, `Get-NetAdapterStatistics`, `Get-NetTCPConnection`, Event Log 4625 per SSH. |
| `tests/test_security.py` | Test unittest stdlib del SAI engine (52 test). |
| `tools/db-backup.py` | Backup online SQLite con rotazione (percorsi/ritenzione via env). |
| `tools/email-report.py` | Report giornaliero via email (HTML), config SMTP/DB via env. |
| `tools/watchdog.py` | Watchdog di allarme via email su problemi gravi (soglie via env). |
| `Dockerfile`, `docker-compose.yml` | Build ed esecuzione del container. |

Storage SQLite (`data/metrics.db`):

| Tabella | Contenuto |
|---|---|
| `metrics` | Serie storica 48h: RAM, disco, rete, fw_drop_rate, ssh_failed/invalid_1h, f2b_banned/total_failed, in/out_peers, listening_count, **sai**. |
| `scans` | Ultima scansione nmap per host (JSON). |
| `hosts` | Elenco server monitorati. |
| `users` | Utenti dashboard (password pbkdf2). |
| `kv` | Segreto firma cookie, impostazioni (`nmap_vuln`, `report_email`). |
| `security_events` | Eventi security deduplicati (timeline Security Changes). |
| `security_peers` | Peer di rete osservati per host (first_seen, last_seen, max_connections). |
| `security_ports` | Porte in ascolto osservate per host (first_seen, last_seen). |

---

## Wireframes

### Dashboard principale

```
┌──────────────────────────────────────────────────────────────────────────┐
│  GP monitor                              aggiornato 16:42 · 5s · 4 server │
├──────────────────────────────────────────────────────────────────────────┤
│  [card srv1]  [card srv2]  [card srv3]  [card srv4]  [+]                 │
│  RAM/disco     RAM/disco    RAM/disco    RAM/disco    aggiungi           │
│  Rete ↓↑ RX    Rete ↓↑ RX   Rete ↓↑ RX   Rete ↓↑ RX                     │
│  ● ok          ● ok         ⚠ warn       ● ok                            │
├──────────────────────────────────────────────────────────────────────────┤
│  Sicurezza — Security Activity Dashboard                       REALTIME ●│
│                                                                          │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────┐    │
│  │ACTIVE    │SSH FAIL  │INVALID   │FW DROP   │FAIL2BAN  │NEW PORTS │    │
│  │  3       │ 147 /h   │ 39 /h    │ 2.4k/m   │ 17       │ 2        │    │
│  └──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘    │
│                                                                          │
│  Server      Timeline SAI                    SAI  Stato                  │
│  ────────────────────────────────────────────────────────────────────   │
│  web01       ▁▁▂▂▃▅▇████▆▅▃▂▃▄▇███████     91  ● ACTIVE ATTACK         │
│  proxy01     ▁▁▁▁▁▂▁▁▁▁▁▂▁▁▁▁▁▁▁▁▁▁▁       8  ● NORMAL                 │
│  docker01    ▁▁▂▃▃▅▅▃▂▂▃▅▇▆▄▃▂▂▂▁▁▂▂      67  ● ELEVATED               │
│  db01        ▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁       —  ○ UNKNOWN                 │
│                                                                          │
│  Security Changes                          [All] [Firewall] [SSH] ...    │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │16:42  docker01   NEW PORT          TCP/2375 su 0.0.0.0  ⚠ high   │   │
│  │16:38  web01      SSH SPIKE         41/h (baseline 2)    high      │   │
│  │16:35  web01      INVALID USERS     14/h                  high      │   │
│  │16:31  proxy01    NEW OUT PEER      10.23.7.18:443        medium    │   │
│  │16:22  web02      FAIL2BAN          banned 8              medium    │   │
│  └──────────────────────────────────────────────────────────────────┘   │
├──────────────────────────────────────────────────────────────────────────┤
│  Flussi di rete — chi comunica con chi                                  │
│  [Sankey: server → IP:porta → servizio]                                 │
└──────────────────────────────────────────────────────────────────────────┘
```

### Drawer Security (click su un host)

```
┌──────────────────────────────────────────────────────────────┐
│  🛡 web01 — Security Activity                          ✕     │
├──────────────────────────────────────────────────────────────┤
│  Stato              ● ACTIVE ATTACK                          │
│  SAI                91                                        │
│  Last sample        4 sec ago                                 │
│  Firewall drop      147 /min                                  │
│  SSH failed         41 /h                                     │
│  Invalid users      14 /h                                     │
│  Fail2ban banned    8                                         │
│  Fail2ban total     156                                       │
│  Listening ports    5                                         │
│  New ports (24h)    1                                         │
│  Inbound peers      23                                        │
│  Outbound peers     7                                         │
│  Established conn   42                                        │
├──────────────────────────────────────────────────────────────┤
│  TIMELINE SAI (1h)                                           │
│  ┌──────────────────────────────────────────────────┐        │
│  │     ╱╲      ╱╲╱╲╱╲                              │        │
│  │    ╱  ╲    ╱      ╲    ╱╲                       │        │
│  │ ╱╱     ╲__╱        ╲__╱  ╲___                  │        │
│  │ ─ ─ ─ 40 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─         │        │
│  │ ─ ─ ─ 75 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─         │        │
│  └──────────────────────────────────────────────────┘        │
├──────────────────────────────────────────────────────────────┤
│  LISTENING VS NMAP REACHABLE                                 │
│  TCP/22     ssh OpenSSH 9.2     [nmap YES] [sensibile]       │
│  TCP/443    nginx 1.24          [nmap YES]                   │
│  TCP/5432   PostgreSQL 15       [nmap NO]  [sensibile]       │
│  TCP/2375   docker              [nmap YES] [NEW] [sensibile] │
│  TCP/9090   —                   [nmap NO]  [NEW]             │
├──────────────────────────────────────────────────────────────┤
│  NETWORK PEERS                                               │
│  10.0.0.5:443     in     NEW       first seen 2m fa          │
│  185.1.2.3:4444   out    NEW       first seen 5m fa          │
│  10.0.0.6:80      in     RARE      first seen 3h fa          │
│  10.0.0.1:53      out    CONFIRMED first seen 2g fa          │
├──────────────────────────────────────────────────────────────┤
│  EVENTI RECENTI (24h)                                        │
│  16:42  NEW PORT          TCP/2375 su 0.0.0.0     high       │
│  16:38  SSH SPIKE         41/h (baseline 2)       high       │
│  16:35  INVALID USERS     14/h                    high       │
│  16:31  NEW OUT PEER      185.1.2.3:4444          medium     │
└──────────────────────────────────────────────────────────────┘
```

### Drill-down: Fleet → Server → Security Activity → Event → Raw evidence

```
Fleet (KPI globali)
  └─► Server (timeline SAI + stato)
        └─► Security Activity (drawer: metriche, porte, peer)
              └─► Event (Security Changes: spike, new port, new peer)
                    └─► Raw observable evidence (fw_dropped_pkts, ssh journal, ss)
```

---

## Requisiti

- Una macchina Linux con **Docker** (+ compose plugin) che faccia da collector.
- Connettività **SSH** dal collector ai target. Va bene qualsiasi rete raggiungibile:
  cloud, datacenter on-premise/CED, LAN o VPN. Per esporre in sicurezza servizi altrimenti privati,
  una mesh come **Tailscale/WireGuard** è un'ottima opzione (zero-config, cifrata) ma **non è richiesta**.
- Sui target: accesso SSH e la sonda a comando forzato — `python3` su Linux/macOS, **PowerShell**
  su Windows (OpenSSH Server). Nessun altro requisito.

---

## Installazione

Tutto da **git**: clona il repository ed esegui l'installer (installa Docker se manca, genera la
chiave di monitoraggio, fa `docker compose up -d --build`):

```bash
git clone <URL-DEL-REPO> gpmonitor
cd gpmonitor
./install.sh
```

Poi configura: copia `collector/.env.example` in `collector/.env` e personalizza
(`MON_HOSTS`, `MON_BIND`, `MON_REPORT_EMAIL`, …), quindi applica:

```bash
cd collector && cp -n .env.example .env && $EDITOR .env
docker compose up -d
```

> La **configurazione** vive in `collector/.env` (in `.gitignore`, **mai committato**): così il
> codice resta pubblico e la tua config privata. Aggiorni con `git pull` + `docker compose up -d --build`.

Oppure, senza installer:

```bash
cd gpmonitor/collector
mkdir -p ssh data
ssh-keygen -t ed25519 -N "" -f ssh/monitor_ed25519 -C "gpmon@$(hostname)"
cp -n .env.example .env    # poi personalizza .env
docker compose up -d --build
```

Per aggiornare: `git pull` e poi `cd collector && docker compose up -d --build`.

> ⚠ **Aggiornamenti**: i sorgenti sono **incorporati nell'immagine** (`COPY` nel Dockerfile),
> NON montati come volume. Dopo aver modificato `app.py`/`dashboard.html`/sonde serve SEMPRE
> `docker compose up -d --build` (un semplice `restart` NON aggiorna).

### Sonda a comando forzato (su ogni target)

Copia la sonda e vincola la chiave pubblica di monitoraggio in `~/.ssh/authorized_keys`
dell'utente target:

```
# Linux: copia collector/monitor-probe.py in /usr/local/bin/monitor-probe.py (755)
command="/usr/local/bin/monitor-probe.py",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding <CHIAVE_PUBBLICA>
# macOS: usa monitor-probe-macos.py
command="/usr/bin/python3 /percorso/monitor-probe-macos.py",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding <CHIAVE_PUBBLICA>
```

**Windows** (OpenSSH Server + PowerShell): copia `collector/monitor-probe-windows.ps1` sul target
(es. `C:\gpmon\monitor-probe-windows.ps1`) e aggiungi la riga a comando forzato nel file
`authorized_keys` dell'utente di monitoraggio (per un utente admin è
`C:\ProgramData\ssh\administrator_authorized_keys`, altrimenti `%USERPROFILE%\.ssh\authorized_keys`):

```
command="powershell -NoProfile -ExecutionPolicy Bypass -File C:\gpmon\monitor-probe-windows.ps1",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding <CHIAVE_PUBBLICA>
```

> Requisiti Windows: Windows 8/Server 2012+ e PowerShell 5.1+. Per contare gli SSH falliti serve
> l'accesso al log **Security** (utente admin o nel gruppo *Event Log Readers*); firewall drop e
> fail2ban non esistono su Windows e vengono riportati come `null` (dato non disponibile ≠ 0).

La chiave pubblica è in `collector/ssh/monitor_ed25519.pub` (la stampa anche `install.sh`).
In alternativa, dalla Config si può usare **Installa sonda + aggiungi** (una password bootstrap
usa-e-getta, mai salvata) per l'auto-installazione su Linux.

### Primo accesso

Apri `http://<MON_BIND>`: il **primo utente** che si registra diventa **admin**; i successivi
restano in attesa di approvazione.

---

## Configurazione (`collector/.env`)

La config sta in `collector/.env` (copia da `.env.example`); la compose la legge via `${MON_*}`.

| Variabile | Significato |
|---|---|
| `MON_HOSTS` | `nome=utente@host` separati da virgola (host = IP o hostname raggiungibile in SSH). |
| `MON_BIND` | Indirizzo:porta di ascolto della web. Mettilo su **rete fidata** (loopback/VPN); evita `0.0.0.0` su IP pubblici. |
| `MON_INTERVAL` | Secondi tra un poll e l'altro (default 15). |
| `MON_RETENTION_HOURS` | Retention delle metriche in ore (default 48; alza per più storico, es. `360` = 15 giorni). |
| `MON_SECURITY_RETENTION_HOURS` | Retention degli eventi security in ore (default 48). |
| `MON_PRUNE_EVERY_S` | Intervallo minimo tra due prune di retention (default 600s): evita di tenere un write-lock a ogni insert. |
| `MON_NMAP` | Abilita la scansione nmap (porte/servizi/OS). |
| `MON_NMAP_DEEP` | `1` = tutte le 65535 porte (`-p-`); `0` = top-1000. |
| `MON_NMAP_VULN` | `1` = correlazione CVE via NSE `vulners`. ⚠ interroga internet: NON più 100% on-premise (toggle anche in Config, persistito in `kv`). |
| `MON_REPORT_EMAIL` | Destinatario di report/avvisi (modificabile anche da Config). |
| `MON_SSH_KEY`, `MON_DATA_DIR` | Percorsi chiave privata e dati nel container. |

La lista host e le impostazioni sono modificabili **a caldo** dalla dashboard (⚙ Config), senza
riavviare.

---

## Sicurezza

- **Esposizione minima**: esponi la web solo su rete fidata (loopback/VPN); i target sono raggiunti via SSH.
- **Sonda read-only a comando forzato**: la chiave di monitoraggio non dà shell, esegue solo la sonda.
- **Nessuna dipendenza esterna** (stdlib), nessun dato verso il cloud (salvo `vulners` se attivato).
- **Auth**: primo utente = admin; password pbkdf2-hmac-sha256; cookie di sessione firmati HMAC (TTL 7g).
- **Segreti** (chiave privata di monitoraggio, `data/`) esclusi dal versionamento via `.gitignore`.

---

## Security Activity Dashboard

La sezione **Sicurezza — Security Activity Dashboard** trasforma i contatori di
sicurezza (firewall, SSH, fail2ban, porte, peer di rete) in una vista realtime
contestualizzata nel tempo. L'intelligenza è tutta **collector-side**: la sonda
resta read-only e invariata.

### SAI — Security Activity Index

Indicatore proprietario **0–100** che rappresenta l'intensità dell'attività di
sicurezza anomala osservata sull'host nel periodo corrente, rispetto alla sua
baseline storica (1h/6h/24h).

> **SAI NON è**: probabilità di compromissione, risk score aziendale, severity
> CVSS, certezza di incidente. Rappresenta solo quanto l'attività osservata si
> discosta dal normale dell'host.

Componenti e pesi (centralizzati in `sai_engine.py`, modificabili):

| Componente | Peso | Fonte |
|---|---|---|
| Firewall DROP rate | 20% | delta contatore iptables vs baseline |
| SSH failed password | 25% | journalctl vs baseline |
| SSH invalid user | 20% | journalctl vs baseline (segnale più forte) |
| Fail2ban banned | 15% | fail2ban-client vs baseline |
| New listening ports | 15% | confronto porte in ascolto vs storico |
| Network peer anomaly | 5% | peer nuovi/rari vs storico |

I pesi si ricalibrano automaticamente sulle sole metriche disponibili (es.
macOS senza fail2ban → i pesi residui si normalizzano a 1.0).

**Principio chiave**: un contatore cumulativo (es. `fw_dropped_pkts = 150000`)
NON indica 150.000 eventi appena avvenuti. Il SAI usa sempre il **delta**
(`current - previous`) diviso per il tempo trascorso. `None` (dato non
disponibile) e `0` (dato disponibile, nessun evento) sono tenuti distinti.

### Stati del server

| Stato | Colore | Significato |
|---|---|---|
| **NORMAL** | 🟢 green | Attività entro baseline. |
| **ELEVATED** | 🟡 yellow | Uno o più segnali sopra baseline, ma senza combinazione sufficiente per attività ostile evidente. |
| **ACTIVE ATTACK** | 🔴 red | Combinazione forte di segnali osservabili (es. SSH failed alto + invalid users + fail2ban attivo). Richiede SAI alto AND almeno una rule composita. |
| **UNKNOWN** | ⚪ gray | Telemetria insufficiente o assente. |

Hysteresis integrato per evitare oscillazioni NORMAL↔ELEVATED↔ACTIVE_ATTACK
ad ogni poll (15s):

```
entra ELEVATED se SAI >= 40
torna NORMAL solo se SAI < 30 per 3 campioni consecutivi

entra ACTIVE ATTACK se SAI >= 75 + rule composita
esce solo se SAI < 60 per 4 campioni consecutivi
```

GPMonitor **non usa** mai termini come COMPROMISED, INFECTED, BREACHED: non
possiede le evidenze per affermarlo.

### Rule compositive per ACTIVE ATTACK

ACTIVE ATTACK non si basa solo sul SAI. Richiede almeno una di:

```
ssh_attack       = ssh_failed_high AND ssh_invalid_warn
bruteforce       = ssh_failed_high AND f2b_banned > 0
firewall_attack  = firewall_rate_high AND new_peer
```

### Security Changes

Feed eventi deduplicati (cooldown per non generare un evento ogni 15s durante
lo stesso attacco):

| Tipo evento | Cooldown | Descrizione |
|---|---|---|
| `firewall_spike` | 5 min | FW drop rate > baseline × 3 |
| `ssh_failed_spike` | 5 min | SSH failed > baseline × 3 |
| `ssh_invalid_spike` | 5 min | Invalid users > baseline × 3 |
| `fail2ban_ban` | 5 min | Banned count > baseline |
| `new_listen_port` | 1 h | Porta in ascolto mai vista prima |
| `removed_listen_port` | 1 h | Porta non più in ascolto |
| `new_inbound_peer` | 1 h | Peer in ingresso mai visto prima |
| `new_outbound_peer` | 1 h | Peer in uscita mai visto prima |
| `connection_spike` | 5 min | Picco connessioni stabilite |
| `scan_exposure_change` | 1 h | Variazione porte raggiungibili nmap |
| `cve_change` | 1 h | Variazione CVE dalla scansione |
| `host_security_unknown` | 15 min | Telemetria security non disponibile |

Filtri per tipo (All/Firewall/SSH/Fail2ban/Ports/Network/Nmap) e finestra
temporale (15m/1h/6h/24h).

### Listening vs Nmap Reachable

Il drawer di dettaglio correla le porte in ascolto locali con la raggiungibilità
dalla scansione nmap:

```
TCP/5432
  Local listening      YES
  Nmap reachable       NO
  → servizio in ascolto ma non esposto dal punto di osservazione nmap

TCP/443
  Local listening      YES
  Nmap reachable       YES
  → servizio in ascolto ed esposto
```

CVE assenti (vulners disattivato) e scan non effettuato sono distinti:
**"N/A" ≠ "0 CVE"**.

### Porte sensibili

Tabella configurabile in `sai_engine.py` (interpretate nel contesto, NON
automaticamente vulnerabili):

```
23    (Telnet)       2375  (Docker)      2376  (Docker TLS)
3306  (MySQL)        5432  (PostgreSQL)  6379  (Redis)
9200  (Elasticsearch) 11211 (Memcached)  27017 (MongoDB)
```

### API Security

| Endpoint | Descrizione |
|---|---|
| `GET /api/security/overview` | KPI globali + stato/SAI per-host. |
| `GET /api/security/history?host=&minutes=` | Serie temporale SAI con bucketing (raw ≤1h, 1m ≤6h, 5m ≤24h, 10m ≤48h). |
| `GET /api/security/events?host=&minutes=&limit=&type=` | Feed eventi security. |
| `GET /api/security/peers?host=` | Peer di rete storici (new/rare/confirmed). |
| `GET /api/security/ports?host=` | Porte in ascolto + correlazione nmap. |

---

## Report & Avvisi (email)

- **Report giornaliero** (`tools/email-report.py`) HTML (tabelle ordinate, badge RAG, grafici a barre
  CSS — Gmail-safe: niente SVG/JS/immagini esterne): salute, Docker, vulnerabilità/CVE per host,
  **analisi attacchi** (minaccia reale vs rumore bloccato), utenze. Cadenze via cron.
- **Watchdog** (`tools/watchdog.py`): controlla periodicamente i dati; su **problema grave**
  (disco/RAM critici, host irraggiungibile, SSH che raggiungono sshd) invia un **warning + il report**.
  Anti-spam con cooldown; soglie configurabili via env. `--test` invia un avviso di esempio.
- **Destinatario**: preferito quello impostato da **Config → Email destinatario** (`kv['report_email']`);
  in mancanza usa `GPMON_REPORT_EMAIL`.
- **Nessuna password** viene mai inviata via email (per scelta di sicurezza).

Entrambi gli script sono **standalone** e si configurano via env (SMTP, DB, soglie). Esempio di cron:

```bash
# variabili condivise (in /etc/environment, in un file sorgente dal cron, o inline)
#   GPMON_DB=/opt/gpmonitor/collector/data/metrics.db
#   GPMON_SMTP_HOST=mail.example.com  GPMON_SMTP_PORT=465  GPMON_SMTP_FROM=monitor@example.com
#   GPMON_SMTP_PASSWORD_FILE=/root/.gpmon/mail_pw   GPMON_REPORT_EMAIL=admin@example.com
#   (SMTP con STARTTLS: GPMON_SMTP_SSL=0 GPMON_SMTP_PORT=587 · cert self-signed: GPMON_SMTP_INSECURE=1)

# report giornaliero alle 08:00
0 8 * * *    /usr/bin/python3 /opt/gpmonitor/collector/tools/email-report.py >> /var/log/gpmon-report.log 2>&1
# watchdog ogni 10 minuti
*/10 * * * * /usr/bin/python3 /opt/gpmonitor/collector/tools/watchdog.py    >> /var/log/gpmon-watchdog.log 2>&1
```

| Variabile | Significato |
|---|---|
| `GPMON_SMTP_HOST` / `GPMON_SMTP_PORT` | Server SMTP e porta (default `localhost:465`). |
| `GPMON_SMTP_SSL` | `1` = SMTP_SSL (default), `0` = SMTP + STARTTLS. |
| `GPMON_SMTP_FROM` / `GPMON_SMTP_USER` | Mittente e utente di login (default USER=FROM). |
| `GPMON_SMTP_PASSWORD` / `GPMON_SMTP_PASSWORD_FILE` | Password SMTP (valore o file). |
| `GPMON_SMTP_INSECURE` | `1` = non verificare il certificato TLS (mailserver self-signed). |
| `GPMON_REPORT_EMAIL` | Destinatario di fallback (se non impostato in dashboard). |
| `GPMON_WD_DISK_CRIT` / `GPMON_WD_MEM_CRIT` / `GPMON_WD_STALE` / `GPMON_WD_SSH_REAL` / `GPMON_WD_COOLDOWN` | Soglie e cooldown del watchdog. |

## Auto-ban scanner

Jail fail2ban che legge i blocchi del firewall e banna gli IP che superano una soglia di
pacchetti bloccati, con **escalation** per i recidivi e **whitelist** blindata (loopback, reti
private, Tailscale, Docker, IP admin). Si banna solo ciò che è già bloccato dal firewall: il
traffico legittimo non è mai candidato.

---

## Backup del database

Lo storico vive in un unico file SQLite (`data/metrics.db`). Il DB gira in **WAL mode**
(`journal_mode=WAL`): reader concorrenti e un writer non si bloccano a vicenda — utile con
retention lunghe e poll paralleli. Per i backup usa `collector/tools/db-backup.py`, che sfrutta
l'**API di backup online** di SQLite (copia coerente anche mentre il collector scrive) e ruota i
file gzippati:

```bash
# backup manuale (dalla cartella collector)
GPMON_DB=data/metrics.db python3 tools/db-backup.py

# cron giornaliero (03:30), tenendo gli ultimi 15 backup
30 3 * * *  GPMON_DB=/opt/gpmonitor/collector/data/metrics.db \
            GPMON_BACKUP_DIR=/opt/gpmonitor/collector/backups \
            GPMON_BACKUP_KEEP=15 \
            /usr/bin/python3 /opt/gpmonitor/collector/tools/db-backup.py >> /var/log/gpmon-backup.log 2>&1
```

| Variabile | Significato |
|---|---|
| `GPMON_DB` | Percorso del DB (default `./data/metrics.db`). |
| `GPMON_BACKUP_DIR` | Cartella dei backup (default `./backups`). |
| `GPMON_BACKUP_KEEP` | Quanti backup giornalieri conservare (default 15). |

---

## API principali

| Endpoint | Metodo | Note |
|---|---|---|
| `/api/latest` | GET | Ultimo snapshot di tutti gli host. |
| `/api/history?host=&minutes=` | GET | Serie storica. |
| `/api/scans` / `/api/scan` | GET/POST | Riepiloghi CVE / avvio scansione (admin). |
| `/api/security/*` | GET | Security Activity Dashboard (overview, history, events, peers, ports). |
| `/api/hosts` | GET/POST/DELETE | Gestione host (admin). |
| `/api/settings` | GET/POST | Impostazioni (`nmap_vuln`, `report_email`) (admin). |
| `/api/register` `/api/login` `/api/logout` `/api/users*` | POST/GET | Auth e gestione utenti. |

---

## Test

Il SAI engine è testato con **unittest stdlib** (52 test in `collector/tests/test_security.py`):

```bash
cd collector && python3 tests/test_security.py -v
```

Copertura: counter delta/reset/None, baseline (median/p95/degradazione), SAI clamp 0–100,
dynamic weight normalization (macOS partial metrics), state transitions + hysteresis,
event deduplication, new/removed port detection, new peer detection, nmap correlation,
host missing/telemetry unavailable.

---

## Contribuire

I contributi sono benvenuti — vedi [CONTRIBUTING.md](CONTRIBUTING.md). In breve: resta
**agentless**, **solo stdlib** (niente pip/CDN/framework), **on-premise** e **general-purpose**
(nessun riferimento a installazioni specifiche, nessun segreto nei sorgenti).

---

## Licenza

Rilasciato sotto licenza **MIT** (vedi [LICENSE](LICENSE)). Progetto open-source: usalo, modificalo
e distribuiscilo liberamente.

---

<p align="center">
  <img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-blue.svg">
  <img alt="Open Source" src="https://img.shields.io/badge/Open_Source-♥-brightgreen.svg">
</p>

<p align="center">
  <strong>Fatto con il ❤️ da Stefano Scaramuzzino</strong>
</p>
