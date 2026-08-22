# gp-monitor

Monitoraggio **agentless** dei server srv1/srv2/srv3 (DOCKER · DISCO · RAM · RETE · attacchi).
Nessun agente installato: un collector interroga i server via **SSH su Tailscale** con una
chiave dedicata a **comando forzato** (può eseguire SOLO la sonda, in sola lettura).

## Architettura

```
                 srv2 (host di monitoraggio, tailnet)
   ┌───────────────────────────────────────────────┐
   │  container gpmon (Docker, network_mode host)    │
   │   • poller: ssh -> monitor-probe.py (JSON)      │
   │   • SQLite (retention 48h) + rate dai contatori │
   │   • web http://10.0.0.2:8888 (solo tailnet)│
   └──────────────┬─────────────┬────────────────────┘
       ssh root@  │   ssh callim.│   ssh root@
       10.0.0.1   10.0.0.2   10.0.0.3
          srv1          srv2(self)        srv3
     /usr/local/bin/monitor-probe.py (comando forzato, sola lettura)
```

## Componenti
- `probe/monitor-probe.py` — sonda read-only (stdlib). Installata su ogni server in
  `/usr/local/bin/monitor-probe.py`, eseguita come **comando forzato** dalla chiave di monitoraggio.
- `collector/app.py` — poller + web (stdlib: http.server, sqlite3, subprocess ssh).
- `collector/dashboard.html` — dashboard self-contained (nessun CDN).
- `collector/{Dockerfile,docker-compose.yml}` — deploy su srv2.

## Sicurezza
- La chiave `monitor_ed25519` è vincolata in `authorized_keys` con
  `command="…",no-pty,no-port-forwarding,…` → non dà una shell, esegue solo la sonda.
- La web è bindata sull'IP **Tailscale** di srv2 → non raggiungibile da Internet.
- La sonda non modifica nulla: legge `/proc`, `docker ps/stats`, `ss`, `iptables -L`,
  `journalctl`, `fail2ban-client status`.

## Gestione
- Avvio/agg.: `cd /opt/gp-monitor && docker compose up -d --build`
- Log: `docker logs -f gpmon`
- Stop/rimozione: `docker compose down` (i dati restano in `./data`)
- Retention/porte/intervallo: variabili `MON_*` nel `docker-compose.yml`.

Dashboard: **http://10.0.0.2:8888** (dalla tailnet).
