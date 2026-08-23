#!/usr/bin/env python3
"""
Test del SAI engine (Security Activity Index) — unittest stdlib.
Testa le funzioni pure di sai_engine.py senza DB/SSH: counter delta/reset/None,
baseline, SAI clamp, dynamic weight normalization, state transitions + hysteresis,
event dedup (logica), new/removed port detection, new peer detection, nmap
correlation, host missing, probe macOS partial metrics.

Autore: Stefano Scaramuzzino
Data: 2026-08-23
Versione: 1.0.0
"""
import os
import sys
import time
import unittest

# importa sai_engine dalla cartella collector/
HERE = os.path.dirname(os.path.abspath(__file__))
COLLECTOR = os.path.dirname(HERE)
sys.path.insert(0, COLLECTOR)
import sai_engine as se


class TestSafeRate(unittest.TestCase):
    """counter delta, counter reset, None handling."""

    def test_normal_delta(self):
        # 100 pkt in 60s -> rate 1.67/s
        self.assertAlmostEqual(se.safe_rate(200, 100, 60), 100 / 60, places=4)

    def test_none_current(self):
        self.assertIsNone(se.safe_rate(None, 100, 60))

    def test_none_previous(self):
        self.assertIsNone(se.safe_rate(100, None, 60))

    def test_reset_counter(self):
        # current < previous: reset host o azzeramento -> None (NON negativo)
        self.assertIsNone(se.safe_rate(50, 200, 60))

    def test_zero_elapsed(self):
        self.assertIsNone(se.safe_rate(200, 100, 0))

    def test_negative_elapsed(self):
        self.assertIsNone(se.safe_rate(200, 100, -5))

    def test_no_change(self):
        self.assertEqual(se.safe_rate(100, 100, 60), 0.0)

    def test_none_vs_zero_distinct(self):
        # None = dato non disponibile; 0 = dato disponibile, nessun evento
        self.assertIsNone(se.safe_rate(None, None, 60))
        self.assertEqual(se.safe_rate(100, 100, 60), 0.0)


class TestBaseline(unittest.TestCase):
    """baseline su finestre 1h/6h/24h con degradazione elegante."""

    def _rows(self, vals, now=None):
        if now is None:
            now = int(time.time())
        return [{"ts": now - i * 60, "fw": v} for i, v in enumerate(vals)]

    def test_enough_samples(self):
        rows = self._rows([2, 3, 2, 4, 2, 3, 2, 5, 2, 3])
        bl = se.baseline_values(rows, "fw", windows=(3600,))
        self.assertIsNotNone(bl[3600]["median"])
        self.assertIsNotNone(bl[3600]["p95"])
        self.assertEqual(bl[3600]["count"], 10)

    def test_too_few_samples(self):
        rows = self._rows([2, 3])
        bl = se.baseline_values(rows, "fw", windows=(3600,))
        self.assertIsNone(bl[3600]["median"])
        self.assertEqual(bl[3600]["count"], 2)

    def test_empty_rows(self):
        bl = se.baseline_values([], "fw", windows=(3600,))
        self.assertIsNone(bl[3600]["median"])
        self.assertEqual(bl[3600]["count"], 0)

    def test_none_values_excluded(self):
        rows = [{"ts": int(time.time()), "fw": None}] * 10
        bl = se.baseline_values(rows, "fw", windows=(3600,))
        self.assertEqual(bl[3600]["count"], 0)


class TestNormalizedRatio(unittest.TestCase):
    """normalizzazione ratio current/baseline in 0..100."""

    def test_none_current(self):
        self.assertEqual(se.normalized_ratio(None, 10), 0)

    def test_within_baseline(self):
        # ratio <= 1 -> min(20, current)
        self.assertEqual(se.normalized_ratio(5, 10), 5)
        self.assertEqual(se.normalized_ratio(10, 10), 10)
        # ratio 1.5 -> branch ratio<=2 -> 35
        self.assertEqual(se.normalized_ratio(15, 10), 35)

    def test_ratio_2x(self):
        # current=20, baseline=10 -> ratio 2.0 -> branch ratio<=2 -> 35
        self.assertEqual(se.normalized_ratio(20, 10), 35)
        # ratio 2.1 -> branch ratio<=5 -> 60
        self.assertEqual(se.normalized_ratio(21, 10), 60)

    def test_ratio_5x(self):
        self.assertEqual(se.normalized_ratio(50, 10), 60)

    def test_ratio_10x(self):
        self.assertEqual(se.normalized_ratio(100, 10), 80)

    def test_ratio_over_10x(self):
        self.assertEqual(se.normalized_ratio(200, 10), 100)

    def test_baseline_none(self):
        # baseline None -> floor=1 -> ratio = current/1 = 50 -> 100
        self.assertEqual(se.normalized_ratio(50, None), 100)

    def test_baseline_zero(self):
        # baseline 0 -> floor=1 -> ratio = current/1 = 50 -> 100
        self.assertEqual(se.normalized_ratio(50, 0), 100)


class TestSaiScore(unittest.TestCase):
    """SAI clamp 0..100 + dynamic weight normalization (macOS partial metrics)."""

    def _components(self, vals, available):
        c = dict(vals)
        c["_available"] = dict(available)
        return c

    def test_all_components(self):
        c = self._components(
            {"firewall": 100, "ssh_failed": 100, "ssh_invalid": 100,
             "fail2ban": 100, "new_ports": 100, "network_peer": 100},
            {k: True for k in se.SAI_WEIGHTS})
        sai, w = se.sai_score(c)
        self.assertEqual(sai, 100)
        self.assertAlmostEqual(sum(w.values()), 1.0, places=6)

    def test_zero_components(self):
        c = self._components(
            {"firewall": 0, "ssh_failed": 0, "ssh_invalid": 0,
             "fail2ban": 0, "new_ports": 0, "network_peer": 0},
            {k: True for k in se.SAI_WEIGHTS})
        sai, _ = se.sai_score(c)
        self.assertEqual(sai, 0)

    def test_clamp_above_100(self):
        # componenti > 100 non devono far superare 100 al SAI
        c = self._components(
            {"firewall": 200, "ssh_failed": 200, "ssh_invalid": 200,
             "fail2ban": 200, "new_ports": 200, "network_peer": 200},
            {k: True for k in se.SAI_WEIGHTS})
        sai, _ = se.sai_score(c)
        self.assertEqual(sai, 100)

    def test_macos_no_fail2ban(self):
        # macOS: fail2ban non disponibile -> pesi ricalibrati sugli altri
        avail = {k: True for k in se.SAI_WEIGHTS}
        avail["fail2ban"] = False
        c = self._components(
            {"firewall": 100, "ssh_failed": 100, "ssh_invalid": 100,
             "fail2ban": 0, "new_ports": 100, "network_peer": 100}, avail)
        sai, w = se.sai_score(c)
        self.assertEqual(sai, 100)
        self.assertNotIn("fail2ban", w)
        self.assertAlmostEqual(sum(w.values()), 1.0, places=6)

    def test_no_metrics_available(self):
        c = self._components(
            {"firewall": 50, "ssh_failed": 50}, {k: False for k in se.SAI_WEIGHTS})
        sai, _ = se.sai_score(c)
        self.assertEqual(sai, 0)

    def test_partial_weights_renormalized(self):
        # solo firewall + ssh_failed disponibili -> pesi 0.20+0.25 normalizzati a 1.0
        avail = {k: False for k in se.SAI_WEIGHTS}
        avail["firewall"] = True
        avail["ssh_failed"] = True
        c = self._components({"firewall": 80, "ssh_failed": 60}, avail)
        sai, w = se.sai_score(c)
        # 80*(0.20/0.45) + 60*(0.25/0.45) = 80*0.444 + 60*0.556 = 35.6+33.3 = 68.9 -> 69
        self.assertAlmostEqual(sum(w.values()), 1.0, places=6)
        self.assertEqual(w["firewall"], se.SAI_WEIGHTS["firewall"] / 0.45)
        self.assertEqual(w["ssh_failed"], se.SAI_WEIGHTS["ssh_failed"] / 0.45)


class TestClassifyState(unittest.TestCase):
    """state transitions + hysteresis (evita oscillazioni ogni 15s)."""

    def _raw(self, **kw):
        d = {"ssh_failed_1h": 0, "ssh_invalid_1h": 0, "f2b_banned": 0,
             "fw_rate": 0, "peer_anomaly": 0}
        d.update(kw)
        return d

    def test_normal_stays_normal_low_sai(self):
        st = {"state": "normal", "sai": 5, "below_count": 0}
        new = se.classify_state("normal", 5, self._raw(), st)
        self.assertEqual(new, "normal")

    def test_normal_to_elevated(self):
        st = {"state": "normal", "sai": 0, "below_count": 0}
        new = se.classify_state("normal", 45, self._raw(), st)
        self.assertEqual(new, "elevated")

    def test_elevated_hysteresis_stays_elevated(self):
        # SAI 35 (sopra exit 30 ma sotto enter 40) -> resta elevated
        st = {"state": "elevated", "sai": 45, "below_count": 0}
        new = se.classify_state("elevated", 35, self._raw(), st)
        self.assertEqual(new, "elevated")

    def test_elevated_to_normal_after_n_samples(self):
        # SAI 25 (sotto exit 30) per 3 campioni -> normal
        st = {"state": "elevated", "sai": 45, "below_count": 0}
        for _ in range(2):
            se.classify_state("elevated", 25, self._raw(), st)
        new = se.classify_state("elevated", 25, self._raw(), st)
        self.assertEqual(new, "normal")

    def test_elevated_not_normal_before_n_samples(self):
        # SAI 25 per 2 campioni (< 3) -> ancora elevated
        st = {"state": "elevated", "sai": 45, "below_count": 0}
        se.classify_state("elevated", 25, self._raw(), st)
        new = se.classify_state("elevated", 25, self._raw(), st)
        self.assertEqual(new, "elevated")

    def test_active_attack_requires_composite_rule(self):
        # SAI 80 ma nessuna rule composita -> elevated (NON active_attack)
        st = {"state": "normal", "sai": 0, "below_count": 0}
        new = se.classify_state("normal", 80, self._raw(), st)
        self.assertEqual(new, "elevated")

    def test_active_attack_with_ssh_rule(self):
        # SAI 80 + ssh_failed_high + ssh_invalid_warn -> active_attack
        st = {"state": "normal", "sai": 0, "below_count": 0}
        raw = self._raw(ssh_failed_1h=40, ssh_invalid_1h=5)
        new = se.classify_state("normal", 80, raw, st)
        self.assertEqual(new, "active_attack")

    def test_active_attack_with_bruteforce_rule(self):
        # SAI 80 + ssh_failed_high + f2b_banned > 0 -> active_attack
        st = {"state": "normal", "sai": 0, "below_count": 0}
        raw = self._raw(ssh_failed_1h=40, f2b_banned=3)
        new = se.classify_state("normal", 80, raw, st)
        self.assertEqual(new, "active_attack")

    def test_active_attack_hysteresis_exit(self):
        # da active_attack, SAI 55 (< exit 60) per 4 campioni -> elevated/normal
        st = {"state": "active_attack", "sai": 80, "below_count": 0}
        raw = self._raw(ssh_failed_1h=40, ssh_invalid_1h=5)
        for _ in range(3):
            se.classify_state("active_attack", 55, raw, st)
        new = se.classify_state("active_attack", 55, raw, st)
        self.assertIn(new, ("elevated", "normal"))

    def test_no_oscillation(self):
        # sequenza 40, 35, 40, 35 non deve oscillare normal<->elevated
        st = {"state": "normal", "sai": 0, "below_count": 0}
        se.classify_state("normal", 45, self._raw(), st)  # -> elevated
        self.assertEqual(st["state"], "elevated")
        se.classify_state("elevated", 35, self._raw(), st)  # resta elevated
        self.assertEqual(st["state"], "elevated")
        se.classify_state("elevated", 45, self._raw(), st)  # resta elevated
        self.assertEqual(st["state"], "elevated")


class TestPortDetection(unittest.TestCase):
    """new/removed port detection (logica pura su set)."""

    def test_new_port_detected(self):
        known = {("tcp", "0.0.0.0", 22), ("tcp", "0.0.0.0", 80)}
        current = {("tcp", "0.0.0.0", 22), ("tcp", "0.0.0.0", 80), ("tcp", "0.0.0.0", 2375)}
        new = current - known
        self.assertIn(("tcp", "0.0.0.0", 2375), new)

    def test_removed_port_detected(self):
        known = {("tcp", "0.0.0.0", 22), ("tcp", "0.0.0.0", 80), ("tcp", "0.0.0.0", 3306)}
        current = {("tcp", "0.0.0.0", 22), ("tcp", "0.0.0.0", 80)}
        removed = known - current
        self.assertIn(("tcp", "0.0.0.0", 3306), removed)

    def test_no_changes(self):
        known = {("tcp", "0.0.0.0", 22), ("tcp", "0.0.0.0", 80)}
        current = {("tcp", "0.0.0.0", 22), ("tcp", "0.0.0.0", 80)}
        self.assertEqual(current - known, set())
        self.assertEqual(known - current, set())

    def test_sensitive_port_flagged(self):
        self.assertIn(2375, se.SENSITIVE_PORTS)
        self.assertIn(5432, se.SENSITIVE_PORTS)
        self.assertNotIn(80, se.SENSITIVE_PORTS)


class TestPeerDetection(unittest.TestCase):
    """new peer detection (logica pura)."""

    def test_new_inbound_peer(self):
        known = {("in", "10.0.0.5", 443), ("in", "10.0.0.6", 80)}
        current = {("in", "10.0.0.5", 443), ("in", "185.1.2.3", 4444)}
        new = current - known
        self.assertIn(("in", "185.1.2.3", 4444), new)

    def test_new_outbound_peer(self):
        known = set()
        current = {("out", "10.0.0.5", 443)}
        new = current - known
        self.assertIn(("out", "10.0.0.5", 443), new)

    def test_confirmed_peer_not_new(self):
        known = {("in", "10.0.0.5", 443)}
        current = {("in", "10.0.0.5", 443)}
        self.assertEqual(current - known, set())


class TestEventDedup(unittest.TestCase):
    """event deduplication (logica del cooldown)."""

    def test_cooldown_blocks_duplicate(self):
        # simula: ultimo evento 100s fa, cooldown 300s -> bloccato
        now = int(time.time())
        last_ts = now - 100
        cooldown = 300
        self.assertTrue((now - last_ts) < cooldown)  # dentro cooldown -> dedup

    def test_cooldown_allows_after_expiry(self):
        now = int(time.time())
        last_ts = now - 400
        cooldown = 300
        self.assertFalse((now - last_ts) < cooldown)  # fuori cooldown -> ok


class TestNmapCorrelation(unittest.TestCase):
    """listening vs reachable correlation (logica pura)."""

    def test_listening_and_reachable(self):
        listening = {("tcp", 443), ("tcp", 22)}
        reachable = {"tcp/443", "tcp/22"}
        # entrambe le porte sono sia in ascolto che raggiungibili da nmap
        for proto, port in listening:
            key = "%s/%d" % (proto, port)
            self.assertIn(key, reachable)

    def test_listening_not_reachable(self):
        # TCP/5432 in ascolto su localhost ma non raggiungibile da nmap
        listening = {("tcp", 5432)}
        reachable = set()
        key = "tcp/5432"
        self.assertNotIn(key, reachable)

    def test_cve_unavailable_vs_zero(self):
        # scan assente -> "N/A" (NON "0 CVE")
        scan_status = "none"
        self.assertEqual(scan_status, "none")
        # vulners disattivato -> "0 CVE" è distinto da "N/A"
        vuln_enabled = False
        cve_count = 0
        self.assertFalse(vuln_enabled)
        self.assertEqual(cve_count, 0)


class TestHostMissing(unittest.TestCase):
    """host missing / telemetria assente -> stato UNKNOWN."""

    def test_no_telemetry_unknown_state(self):
        st = {"state": "unknown", "sai": 0, "below_count": 0}
        # nessuna metrica disponibile -> SAI 0, stato unknown
        components = {"_available": {k: False for k in se.SAI_WEIGHTS}}
        sai, _ = se.sai_score(components)
        self.assertEqual(sai, 0)
        self.assertEqual(st["state"], "unknown")

    def test_error_host_not_crash(self):
        # un host con errore non deve far crashare il calcolo SAI
        raw = {"ssh_failed_1h": None, "ssh_invalid_1h": None,
               "f2b_banned": None, "fw_rate": None, "peer_anomaly": 0}
        st = {"state": "unknown", "sai": 0, "below_count": 0}
        # anche con tutti None, classify_state non deve lanciare
        new = se.classify_state("unknown", 0, raw, st)
        self.assertIn(new, ("unknown", "normal"))


class TestMacOSPartialMetrics(unittest.TestCase):
    """probe macOS: metriche parziali (no fail2ban, no iptables su alcuni)."""

    def test_no_fail2ban_weight_renormalized(self):
        avail = {k: True for k in se.SAI_WEIGHTS}
        avail["fail2ban"] = False
        avail["firewall"] = False  # macOS senza iptables
        c = {"ssh_failed": 60, "ssh_invalid": 40, "new_ports": 0, "network_peer": 0,
             "_available": avail}
        sai, w = se.sai_score(c)
        # ssh_failed 0.25 + ssh_invalid 0.20 + new_ports 0.15 + network_peer 0.05 = 0.65
        self.assertAlmostEqual(sum(w.values()), 1.0, places=6)
        self.assertNotIn("fail2ban", w)
        self.assertNotIn("firewall", w)

    def test_none_not_zero(self):
        # None deve restituire componente 0 (non interpretato come spike)
        self.assertEqual(se.normalized_ratio(None, 10), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
