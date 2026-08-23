#!/usr/bin/env python3
"""
SAI (Security Activity Index) engine — funzioni pure, testabili senza DB/SSH.
Estratte da app.py per consentire unittest stdlib isolati. app.py importa
questo modulo e usa queste funzioni con i propri dati (rows SQLite, stato
in-memory). Tutto collector-side: la sonda resta read-only e invariata.

Autore: Stefano Scaramuzzino
Data: 2026-08-23
Versione: 1.0.0
"""
import math
import statistics


# Pesi dei componenti SAI (sommano a 1.0). Centralizzati e modificabili.
SAI_WEIGHTS = {
    "firewall": 0.20,
    "ssh_failed": 0.25,
    "ssh_invalid": 0.20,
    "fail2ban": 0.15,
    "new_ports": 0.15,
    "network_peer": 0.05,
}

SECURITY_THRESHOLDS = {
    "ssh_failed_warn": 10,
    "ssh_failed_high": 30,
    "ssh_invalid_warn": 3,
    "ssh_invalid_high": 10,
    "firewall_rate_warn": 20,
    "firewall_rate_high": 100,
    "new_port_score": 40,
    "peer_anomaly_score": 30,
    "spike_multiplier": 3.0,
    "spike_min_absolute": 5,
}

SAI_HYSTERESIS = {
    "elevated_enter": 40,
    "elevated_exit": 30,
    "elevated_exit_samples": 3,
    "attack_enter": 75,
    "attack_exit": 60,
    "attack_exit_samples": 4,
}

SENSITIVE_PORTS = {23, 2375, 2376, 3306, 5432, 6379, 9200, 11211, 27017}


def safe_rate(current, previous, elapsed):
    """Rate da due contatori cumulativi. Gestisce reset/wrap/None.
    Un contatore cumulativo (es. fw_dropped_pkts=150000) NON indica 150000
    eventi appena avvenuti: serve il delta. Se current < previous (reset host
    o azzeramento contatore) restituisce None invece di un valore negativo o
    fittiziamente grande. None = dato non disponibile, 0 = dato disponibile
    ma nessun evento: i due casi vanno tenuti distinti."""
    if current is None or previous is None:
        return None
    if elapsed <= 0:
        return None
    if current < previous:
        return None  # reset/wrap: non possiamo calcolare un rate affidabile
    return (current - previous) / elapsed


def baseline_values(rows, field, windows=(3600, 21600, 86400), now=None):
    """Baseline per una metrica su finestre 1h/6h/24h. Usa median (robusto agli
    outlier) e p95. Degrada elegantemente se non ci sono abbastanza campioni.
    rows = lista di dict con chiavi 'ts' e field. now = timestamp riferimento."""
    import time
    if now is None:
        now = int(time.time())
    out = {}
    for w in windows:
        vals = [r[field] for r in rows
                if r.get(field) is not None and (now - r["ts"]) <= w]
        if len(vals) < 5:
            out[w] = {"median": None, "p95": None, "count": len(vals)}
            continue
        med = statistics.median(vals)
        s = sorted(vals)
        idx = min(len(s) - 1, int(math.ceil(0.95 * len(s))) - 1)
        out[w] = {"median": med, "p95": s[idx], "count": len(vals)}
    return out


def normalized_ratio(current, baseline, floor=1.0):
    """Normalizza un ratio current/baseline in 0..100 per il SAI.
    baseline=0 o None -> usa floor per evitare divisione per zero. Ratio <=1
    significa 'entro baseline' -> basso. Ratio crescente -> SAI crescente."""
    if current is None:
        return 0
    b = max(float(baseline or 0), floor)
    ratio = current / b
    if ratio <= 1:
        return min(20, float(current))
    if ratio <= 2:
        return 35
    if ratio <= 5:
        return 60
    if ratio <= 10:
        return 80
    return 100


def sai_score(components):
    """Media pesata dei componenti con ricalibrazione pesi sulle sole metriche
    disponibili (macOS non ha fail2ban, ecc.). Clamp 0..100.
    components = {comp_name: 0..100, "_available": {comp_name: bool}}.
    Ritorna (sai_int, weights_dict)."""
    avail = {k: v for k, v in components.get("_available", {}).items() if v}
    if not avail:
        return 0, dict(SAI_WEIGHTS)
    total_w = sum(SAI_WEIGHTS[k] for k in avail)
    if total_w <= 0:
        return 0, {}
    weights = {k: SAI_WEIGHTS[k] / total_w for k in avail}
    sai = sum(components[k] * weights[k] for k in avail)
    return max(0, min(100, int(round(sai)))), weights


def classify_state(prev_state, sai, raw, state_obj, hysteresis=None, thresholds=None):
    """Classifica lo stato con hysteresis per evitare oscillazioni ogni 15s.
    ACTIVE ATTACK richiede SAI alto AND almeno una rule composita (non basta
    il SAI da solo). Mai usare COMPROMISED/INFECTED/BREACHED: GPMonitor non ha
    le evidenze per affermarlo.
    prev_state = stato precedente (normal/elevated/active_attack/unknown)
    sai = SAI corrente (0-100)
    raw = dict con ssh_failed_1h, ssh_invalid_1h, f2b_banned, fw_rate, peer_anomaly
    state_obj = dict di stato in-memory {state, sai, below_count} (modificato in-place)
    Ritorna il nuovo stato."""
    hy = hysteresis or SAI_HYSTERESIS
    th = thresholds or SECURITY_THRESHOLDS
    # rule compositive per ACTIVE ATTACK
    ssh_attack = (raw.get("ssh_failed_1h") or 0) >= th["ssh_failed_high"] and \
                 (raw.get("ssh_invalid_1h") or 0) >= th["ssh_invalid_warn"]
    bruteforce = (raw.get("ssh_failed_1h") or 0) >= th["ssh_failed_high"] and \
                 (raw.get("f2b_banned") or 0) > 0
    fw_attack = (raw.get("fw_rate") or 0) >= th["firewall_rate_high"] and \
                (raw.get("peer_anomaly") or 0) > 0
    composite_attack = ssh_attack or bruteforce or fw_attack
    new_state = prev_state
    below = state_obj.get("below_count", 0)
    if prev_state != "active_attack" and sai >= hy["attack_enter"] and composite_attack:
        new_state = "active_attack"
        below = 0
    elif prev_state == "active_attack":
        if sai < hy["attack_exit"]:
            below += 1
            if below >= hy["attack_exit_samples"]:
                new_state = "elevated" if sai >= hy["elevated_enter"] else "normal"
                below = 0
        else:
            below = 0
    elif prev_state == "elevated":
        if sai < hy["elevated_exit"]:
            below += 1
            if below >= hy["elevated_exit_samples"]:
                new_state = "normal"
                below = 0
        elif sai >= hy["attack_enter"] and composite_attack:
            new_state = "active_attack"
            below = 0
        else:
            below = 0
    else:  # normal o unknown
        if sai >= hy["elevated_enter"]:
            new_state = "elevated"
            below = 0
        elif sai >= hy["attack_enter"] and composite_attack:
            new_state = "active_attack"
            below = 0
    state_obj["state"] = new_state
    state_obj["sai"] = sai
    state_obj["below_count"] = below
    return new_state
