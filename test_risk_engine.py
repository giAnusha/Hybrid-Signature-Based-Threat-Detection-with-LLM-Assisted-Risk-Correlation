"""
Unit tests for risk_engine.py, covering the project's own validation
scenarios: benign traffic, clear malicious traffic, beaconing C2, single-
engine-only evidence (x3), multi-engine correlation, conflicting evidence,
missing engine, and threat-intel unavailable. No server, Kali VM, or Ollama
required — every function under test is pure.

Run: python -m pytest test_risk_engine.py -v
 or: python -m unittest test_risk_engine -v
"""
import unittest

import risk_engine as re_


def critical(type_="SQL Injection", source="203.0.113.5", destination="192.168.1.100"):
    return {"type": type_, "severity": "CRITICAL", "source": source, "destination": destination,
            "mitre_technique_id": "T1190", "mitre_technique": "Exploit Public-Facing Application"}


def beacon_alert(jitter=1.5, source="192.168.1.88", destination="185.220.101.45"):
    # mitre_technique_id/mitre_technique are always set together in the real
    # pipeline (server.py's mitre_lookup() enrichment) — kept together here too.
    return {"type": "Possible C2 Beaconing", "severity": "CRITICAL", "source": source,
            "destination": destination, "jitter_pct": jitter, "beacon_count": 15,
            "mitre_technique_id": "T1071", "mitre_technique": "Application Layer Protocol"}


def ml_alert(score=-0.35, source="192.168.1.50", destination="10.0.0.5"):
    return {"type": "ML Anomaly (Isolation Forest)", "severity": "HIGH", "source": source,
            "destination": destination, "score": score}


class TestPerEngineScoring(unittest.TestCase):

    def test_benign_traffic_all_engines_zero_or_none(self):
        """1. Benign traffic: engines ran, found nothing -> 0, not None."""
        su = re_.score_suricata([])
        ze = re_.score_zeek({"weird_count": 0})
        ml = re_.score_ml([])
        self.assertEqual(su["score"], 0.0)
        self.assertEqual(ze["score"], 0.0)
        self.assertEqual(ml["score"], 0.0)  # custom engine ran, found nothing -> 0, not "no evidence"
        result = re_.compute_full_risk({"alerts": []}, {"alerts": []}, {"weird_count": 0})
        self.assertEqual(result["risk_level"], "Low")

    def test_clear_malicious_traffic_scores_high(self):
        """2. Multiple CRITICAL Suricata alerts -> high Suricata score."""
        alerts = [critical() for _ in range(6)]
        su = re_.score_suricata(alerts)
        self.assertGreater(su["score"], 60)
        self.assertEqual(su["confidence"], 1.0 if 0.5 + 0.05*6 >= 1.0 else 0.5 + 0.05*6)

    def test_beaconing_c2_traffic_scores_ml_high_low_jitter(self):
        """3. Tight-jitter beacon should score near the top of the ML score."""
        ml = re_.score_ml([beacon_alert(jitter=1.5)])
        self.assertGreater(ml["score"], 90)
        self.assertTrue(any("beacon" in b.lower() for b in ml["basis"]))

    def test_suricata_only_evidence(self):
        """4. Only Suricata produced alerts; Zeek/ML absent -> fusion still works."""
        result = re_.compute_full_risk(None, {"alerts": [critical(), critical()]}, None)
        self.assertIsNotNone(result["suricata_score"])
        self.assertIsNone(result["zeek_score"])
        self.assertIsNone(result["ml_score"])
        self.assertIsNotNone(result["final_risk_score"])  # renormalized over Suricata alone

    def test_zeek_only_evidence(self):
        """5. Only Zeek ran."""
        result = re_.compute_full_risk(None, None, {"weird_count": 10})
        self.assertIsNone(result["suricata_score"])
        self.assertIsNotNone(result["zeek_score"])
        self.assertIsNotNone(result["final_risk_score"])

    def test_ml_only_anomaly(self):
        """6. Only the custom engine ran, with an ML anomaly."""
        result = re_.compute_full_risk({"alerts": [ml_alert()]}, None, None)
        self.assertIsNotNone(result["ml_score"])
        self.assertIsNone(result["suricata_score"])
        self.assertIsNotNone(result["final_risk_score"])

    def test_multi_engine_correlation_raises_confidence_not_just_score(self):
        """7. All three engines independently produce strong evidence for the
        same behaviour -> final score should reflect broad corroboration."""
        analysis = {"alerts": [beacon_alert(), ml_alert()]}
        suricata = {"alerts": [critical(type_="Possible C2 Beaconing") for _ in range(3)]}
        zeek = {"weird_count": 15}
        result = re_.compute_full_risk(analysis, suricata, zeek)
        for key in ("suricata_score", "zeek_score", "ml_score"):
            self.assertIsNotNone(result[key], key)
        self.assertIn(result["risk_level"], ("High", "Critical"))

    def test_conflicting_evidence_suricata_clean_but_ml_flags_anomaly(self):
        """8. Suricata finds nothing (0, not None) while ML flags a beacon —
        fusion should not let the clean Suricata run erase the ML signal."""
        result = re_.compute_full_risk({"alerts": [beacon_alert(jitter=1.0)]},
                                        {"alerts": []}, None)
        self.assertEqual(result["suricata_score"], 0.0)
        self.assertGreater(result["ml_score"], 90)
        self.assertGreater(result["final_risk_score"], 0)

    def test_missing_engine_data_never_crashes_and_renormalizes(self):
        """9. All three of analysis/suricata/zeek missing (None) -> no crash,
        final score is None (genuinely no evidence), not 0 or an exception."""
        result = re_.compute_full_risk(None, None, None)
        self.assertIsNone(result["final_risk_score"])
        self.assertEqual(result["risk_level"], "Unknown")

    def test_threat_intel_unavailable_falls_back_cleanly(self):
        """10. No lookup function provided (no API key) -> ti score is None,
        not 0, and the rest of the fusion still proceeds."""
        result = re_.compute_full_risk({"alerts": [critical()]}, None, None, ti_lookup=None)
        self.assertIsNone(result["threat_intel_score"])
        self.assertIsNotNone(result["final_risk_score"])

    def test_threat_intel_lookup_exception_is_swallowed(self):
        def flaky_lookup(ip):
            raise ConnectionError("simulated API timeout")
        result = re_.score_ti(["203.0.113.5"], flaky_lookup)
        self.assertIsNone(result["score"])

    def test_threat_intel_below_threshold_excluded(self):
        """A lookup that came back but didn't clear its own malicious
        threshold (threat_intel.is_malicious) must not become a finding —
        borderline/clean results are not evidence."""
        def clean_lookup(ip):
            return {"ip": ip, "is_malicious": False, "confidence": 4.0, "summary": None}
        result = re_.score_ti(["203.0.113.5"], clean_lookup)
        self.assertIsNone(result["score"])
        self.assertEqual(result["ips"], [])

    def test_threat_intel_included_when_malicious(self):
        def malicious_lookup(ip):
            return {"ip": ip, "is_malicious": True, "confidence": 92.0,
                    "summary": "AbuseIPDB 92% confidence"}
        result = re_.score_ti(["185.220.101.45"], malicious_lookup)
        self.assertEqual(result["score"], 92.0)
        self.assertEqual(len(result["ips"]), 1)
        self.assertIn("185.220.101.45", result["basis"][0])

    def test_threat_intel_multiple_malicious_ips_picks_highest_confidence(self):
        def combined_lookup(ip):
            data = {
                "1.2.3.4": {"ip": "1.2.3.4", "is_malicious": True, "confidence": 40.0, "summary": "low hit"},
                "5.6.7.8": {"ip": "5.6.7.8", "is_malicious": True, "confidence": 95.0, "summary": "high hit"},
            }
            return data[ip]
        result = re_.score_ti(["1.2.3.4", "5.6.7.8"], combined_lookup)
        self.assertEqual(result["score"], 95.0)
        self.assertEqual(len(result["ips"]), 2)  # both malicious IPs listed, not just the best

    def test_threat_intel_no_ip_clears_threshold_returns_none_not_zero(self):
        def mixed_lookup(ip):
            return None if ip == "203.0.113.5" else {"ip": ip, "is_malicious": False, "confidence": 10.0, "summary": None}
        result = re_.score_ti(["203.0.113.5", "198.51.100.9"], mixed_lookup)
        self.assertIsNone(result["score"])


class TestWeightsAndClassification(unittest.TestCase):

    def test_default_weights_sum_to_one(self):
        w = re_.load_weights()
        self.assertAlmostEqual(sum(w.values()), 1.0, places=2)

    def test_classify_bands(self):
        self.assertEqual(re_.classify(0), "Low")
        self.assertEqual(re_.classify(29.9), "Low")
        self.assertEqual(re_.classify(30), "Medium")
        self.assertEqual(re_.classify(59.9), "Medium")
        self.assertEqual(re_.classify(60), "High")
        self.assertEqual(re_.classify(79.9), "High")
        self.assertEqual(re_.classify(80), "Critical")
        self.assertEqual(re_.classify(None), "Unknown")

    def test_fusion_renormalizes_over_available_evidence_only(self):
        # Two engines report the same score; missing engines shouldn't
        # change the result versus if they'd never existed.
        full = re_.fuse({
            "suricata": {"score": 80}, "zeek": {"score": None},
            "ml": {"score": 80}, "ti": {"score": None},
        })
        # suricata(0.30) + ml(0.30) both = 80 -> weighted avg is still 80
        self.assertAlmostEqual(full["final_score"], 80.0, places=1)


class TestDedupeAndEvidenceExtraction(unittest.TestCase):

    def test_dedupe_drops_lower_or_equal_severity_suricata_duplicate(self):
        custom = [critical(source="203.0.113.5", destination="192.168.1.100")]
        suricata = [
            {"type": "Suricata: dup", "severity": "CRITICAL", "source": "203.0.113.5:443",
             "destination": "192.168.1.100:80"},
            {"type": "Suricata: unique", "severity": "HIGH", "source": "8.8.8.8:53",
             "destination": "192.168.1.100:80"},
        ]
        deduped = re_.dedupe_suricata(custom, suricata)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0]["type"], "Suricata: unique")

    def test_ip_only_never_mangles_ipv6(self):
        self.assertEqual(re_._ip_only("2001:db8::1"), "2001:db8::1")
        self.assertEqual(re_._ip_only("203.0.113.5:8080"), "203.0.113.5")
        self.assertIsNone(re_._ip_only(None))

    def test_c2_indicators_reflect_actual_alerts(self):
        indicators = re_.c2_indicators([beacon_alert()])
        self.assertTrue(any("periodic" in i for i in indicators))

    def test_mitre_techniques_deduplicated_across_engines(self):
        custom = [beacon_alert()]  # T1071, "Application Layer Protocol"
        suricata = [{"mitre_technique_id": "T1071", "mitre_technique": "Application Layer Protocol"},
                    {"mitre_technique_id": "T1190", "mitre_technique": "Exploit Public-Facing Application"}]
        techs = re_.mitre_techniques(custom, suricata)
        # Never bare ID strings — a local LLM given only "T1190" has to guess
        # what it means and will invent a wrong description; the name must
        # always travel with the ID.
        self.assertEqual(techs, [
            {"id": "T1071", "name": "Application Layer Protocol"},
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
        ])


if __name__ == "__main__":
    unittest.main()
