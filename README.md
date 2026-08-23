# GPMonitor

Sistema di monitoraggio **agentless** e **100% on-premise** per flotte di server Linux (e Mac),
scritto su misura in **solo Python stdlib** (nessun `pip`, nessun CDN, nessuna telemetria/cloud).

Un collector interroga i server via **SSH** — in qualsiasi contesto: **cloud** (VPS/istanze),
**on-premise** in un datacenter/CED, **LAN** o **VPN** — con una chiave dedicata a **comando
forzato** (che può eseguire SOLO la sonda, in sola lettura).
Raccoglie CPU/RAM, disco, rete,
connessioni, container Docker, sicurezza (firewall, SSH, fail2ban) e — via `nmap` — porte,
servizi e CVE. Dashboard web con grafici SVG vanilla, report email giornalieri, watchdog di
allarme e auto-ban degli scanner.

---

## Caratteristiche

- **Agentless**: nessun demone installato sui target — solo una sonda-script eseguita via SSH a
  comando forzato (read-only). Un OS = una sonda-script (`monitor-probe.py` per Linux,
  `monitor-probe-macos.py` per macOS), scelta in base al sistema. Mai un agente compilato.
- **On-premise / stdlib**: nessuna dipendenza esterna, nessun traffico verso il cloud
  (unica eccezione opzionale e disattivabile: la correlazione CVE via `vulners`, vedi sotto).
- **Dashboard web** (SVG vanilla): card per host (RAM/disco), strip Rete e Sicurezza con
  grafici temporali multi-linea, Sankey dei flussi di rete, dashboard Docker per server in stile
  Grafana, KPI di sicurezza RAG, drawer di scansione nmap con CVE e remediation.
- **Sicurezza**: web in ascolto solo su rete fidata, autenticazione (primo utente = admin),
  cookie di sessione firmati HMAC, gestione utenti.
- **Report & Avvisi via email**: report giornaliero HTML (tabelle, badge RAG, grafici a barre) e
  watchdog che avvisa su problemi gravi. Destinatario configurabile dalla dashboard.
- **Auto-ban** degli scanner aggressivi (fail2ban) con whitelist blindata.
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
   │   • SQLite (retention 48h): metrics, scans, users, kv  │
   │   • nmap (dal container) verso i target                │
   │   • web http://<MON_BIND>:8888  (solo su rete fidata)   │
   └───────────┬───────────────┬───────────────┬────────────┘
        ssh    │        ssh     │        ssh     │
        srv1   │        srv2    │        srv3    │   (comando forzato, read-only)
     /usr/local/bin/monitor-probe.py  ->  stampa un JSON e termina
```

Componenti (cartella `collector/`):

| File | Ruolo |
|---|---|
| `app.py` | Collector + web server (http.server) + API + scheduler nmap. Single-source di versione/build/autore. |
| `dashboard.html` | Interfaccia web (SVG vanilla, nessun framework). |
| `login.html` | Pagina di login/registrazione. |
| `monitor-probe.py` | Sonda **Linux** (JSON): RAM (`/proc/meminfo`), disco (`findmnt`), rete (`/proc/net/dev`), conn (`ss`), docker (`docker ps/stats`), sicurezza (drop iptables/ip6tables, SSH da journal, fail2ban, porte). |
| `monitor-probe-macos.py` | Sonda **macOS** (stesso schema JSON): `sysctl`/`vm_stat`, `df`, `netstat`. |
| `Dockerfile`, `docker-compose.yml` | Build ed esecuzione del container. |

Storage SQLite (`data/metrics.db`): `metrics` (serie 48h), `scans` (ultima scansione nmap per
host, JSON), `hosts` (elenco server), `users` (utenti dashboard, password pbkdf2), `kv`
(segreto firma cookie, impostazioni: `nmap_vuln`, `report_email`).

---

## Requisiti

- Una macchina Linux con **Docker** (+ compose plugin) che faccia da collector.
- Connettività **SSH** dal collector ai target. Va bene qualsiasi rete raggiungibile:
  cloud, datacenter on-premise/CED, LAN o VPN. Per esporre in sicurezza servizi altrimenti privati,
  una mesh come **Tailscale/WireGuard** è un'ottima opzione (zero-config, cifrata) ma **non è richiesta**.
- Sui target: `python3` e accesso SSH; la sonda gira a comando forzato.

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
| `MON_RETENTION_HOURS` | Retention delle metriche (default 48). |
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

## Report & Avvisi (email)

- **Report giornaliero** HTML (tabelle ordinate, badge RAG, grafici a barre CSS — Gmail-safe:
  niente SVG/JS/immagini esterne): salute, Docker, vulnerabilità/CVE per host, **analisi attacchi**
  (minaccia reale vs rumore bloccato), utenze. Cadenze via cron.
- **Watchdog**: controlla periodicamente i dati; su **problema grave** (disco/RAM critici, host
  irraggiungibile, SSH che raggiungono sshd) invia un **warning + il report**. Anti-spam con cooldown.
- **Destinatario**: impostabile da **Config → Email destinatario** (`kv['report_email']`).
- **Nessuna password** viene mai inviata via email (per scelta di sicurezza).

## Auto-ban scanner

Jail fail2ban che legge i blocchi del firewall e banna gli IP che superano una soglia di
pacchetti bloccati, con **escalation** per i recidivi e **whitelist** blindata (loopback, reti
private, Tailscale, Docker, IP admin). Si banna solo ciò che è già bloccato dal firewall: il
traffico legittimo non è mai candidato.

---

## API principali

| Endpoint | Metodo | Note |
|---|---|---|
| `/api/latest` | GET | Ultimo snapshot di tutti gli host. |
| `/api/history?host=&minutes=` | GET | Serie storica. |
| `/api/scans` / `/api/scan` | GET/POST | Riepiloghi CVE / avvio scansione (admin). |
| `/api/hosts` | GET/POST/DELETE | Gestione host (admin). |
| `/api/settings` | GET/POST | Impostazioni (`nmap_vuln`, `report_email`) (admin). |
| `/api/register` `/api/login` `/api/logout` `/api/users*` | POST/GET | Auth e gestione utenti. |

---

## Contribuire

I contributi sono benvenuti — vedi [CONTRIBUTING.md](CONTRIBUTING.md). In breve: resta
**agentless**, **solo stdlib** (niente pip/CDN/framework), **on-premise** e **general-purpose**
(nessun riferimento a installazioni specifiche, nessun segreto nei sorgenti).

## Licenza

Rilasciato sotto licenza **MIT** (vedi [LICENSE](LICENSE)). Progetto open-source: usalo, modificalo
e distribuiscilo liberamente.

## Autore

**Author: Stefano Scaramuzzino**
