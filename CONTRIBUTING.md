# Contribuire a GPMonitor

Grazie per l'interesse! GPMonitor è un progetto **open-source** (MIT). I contributi sono benvenuti.

## Principi di progetto (da rispettare nelle PR)

- **Agentless**: nessun agente/demone installato sui target. La raccolta avviene via SSH a
  **comando forzato** (la chiave può eseguire SOLO la sonda, in sola lettura). Niente componenti
  che richiedano installazioni persistenti sui server monitorati.
- **Solo stdlib**: nessuna dipendenza `pip`, nessun CDN, nessun framework JS. Collector, sonde e
  dashboard usano esclusivamente la libreria standard di Python e SVG/JS vanilla.
- **On-premise**: nessun traffico verso servizi esterni. L'unica eccezione, opzionale e
  disattivabile, è la correlazione CVE via `vulners` (chiaramente segnalata).
- **General-purpose**: niente riferimenti a un'installazione specifica (host, IP, email, hostname).
  Usa placeholder generici.
- **Sicurezza prima di tutto**: nessun segreto nei sorgenti o nella history; la web va tenuta su
  rete fidata; le sonde restano read-only.

## Come proporre una modifica

1. Fai un fork e crea un branch descrittivo (`feat/...`, `fix/...`).
2. Sviluppa e verifica in locale:
   - `python3 -m py_compile collector/app.py`
   - controlla il JS estraendo i blocchi `<script>` di `dashboard.html` (es. `node --check`).
   - prova il build: `cd collector && docker compose up -d --build`.
3. Commit chiari e atomici. **Nessun trailer di co-autore**: l'autore è chi apre la PR.
4. Apri una Pull Request descrivendo cosa cambia e perché.

## Aggiungere il supporto a un nuovo OS

Il modello è **una sonda-script per OS** (Linux, macOS, …) che emette lo **stesso schema JSON**.
Vedi `collector/monitor-probe.py` (Linux) e `collector/monitor-probe-macos.py` (macOS) come
riferimento: aggiungi la tua sonda mantenendo le stesse chiavi, con `null`/liste vuote dove una
metrica non è applicabile.

## Segnalazioni

Apri una issue con: versione (badge in dashboard), OS del collector e dei target, e i log utili
(`docker compose logs`).
