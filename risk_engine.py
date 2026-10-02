"""
Risk fusion engine — combines independent evidence from Suricata, Zeek, the
custom behavioural/ML engine, and (optionally) threat intelligence into one
explainable Final Risk Score /100.

Design principles (see project documentation for the full rationale):
  * Deterministic. No LLM, no randomness. Every number here can be traced
    back to a specific alert or log field.
  * Missing evidence is `None`, never 0 — 0 would falsely claim "checked,
    clean" when an engine simply didn't run (Kali VM off, no API key, etc).
  * Fusion renormalizes over only the evidence that's actually present, so
    one missing engine never silently drags the score down.
  * Every score comes with a short human-readable `basis` list — the exact
    evidence the number is based on — so the dashboard/LLM never has to
    "explain" an opaque number.

This module has no Flask, network, or subprocess dependency, by design —
every function here is a pure function of its inputs and is exercised
directly by test_risk_engine.py without needing the server, the Kali VM,
or Ollama running.
"""
import ipaddress
import json
import math
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEIGHTS_FILE = os.path.join(BASE_DIR, "risk_weights.json")

# Suricata/Zeek/ML weighted equal-highest as the two independent
# judgment-making engines (one signature-based, one behavioural); Zeek lower
# since it only describes traffic, never judges it; threat intel lower as a
# third-party, possibly-stale signal. Sums to 1.0. Override via
# risk_weights.json — never edit these defaults to tune a specific capture.
DEFAULT_WEIGHTS = {"suricata": 0.30, "zeek": 0.20, "ml": 0.30, "ti": 0.20}

SEV_PTS = {"CRITICAL": 30, "HIGH": 18, "MEDIUM": 8, "LOW": 2}
SEV_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


def load_weights() -> dict:
    """Loads fusion weights from risk_weights.json; falls back to the
    documented defaults if the file is missing, malformed, or doesn't sum
    to 1.0 (within rounding tolerance)."""
    try:
        with open(WEIGHTS_FILE, encoding="utf-8") as f:
            raw = json.load(f)
        # Only the four known weight keys are read — an explanatory
        # "_comment" string (or any other extra key) in the file is ignored
        # rather than breaking the sum-to-1.0 check.
        w = {k: float(raw[k]) for k in DEFAULT_WEIGHTS if k in raw}
        if len(w) != len(DEFAULT_WEIGHTS) or abs(sum(w.values()) - 1.0) > 0.02:
            raise ValueError("weights missing a key or don't sum to 1.0")
        return w
    except Exception:
        return dict(DEFAULT_WEIGHTS)


def classify(score: float | None) -> str:
    if score is None:
        return "Unknown"
    if score < 30:
        return "Low"
    if score < 60:
        return "Medium"
    if score < 80:
        return "High"
    return "Critical"


# ── Per-engine scoring ──────────────────────────────────────────────────────

def score_suricata(alerts: list | None) -> dict:
    """alerts=None means Suricata was not run at all (VM off, error) —
    distinct from alerts=[] which means it ran and found nothing."""
    if alerts is None:
        return {"score": None, "confidence": 0.0, "basis": []}
    if not alerts:
        return {"score": 0.0, "confidence": 0.5, "basis": ["Suricata ran; no signature matches"]}
    raw = sum(SEV_PTS.get(a.get("severity", "LOW"), 0) for a in alerts)
    # Saturating curve, not a hard cap: diminishing returns so one CRITICAL
    # alert alone (raw=30) scores ~22/100 (needs corroboration), while ~10
    # CRITICALs (raw=300) saturate toward ~92/100.
    score = 100.0 * (1 - math.exp(-raw / 120.0))
    crit = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
    high = sum(1 for a in alerts if a.get("severity") == "HIGH")
    basis = [f"{len(alerts)} signature match(es): {crit} CRITICAL, {high} HIGH"]
    return {"score": round(score, 1), "confidence": min(1.0, 0.5 + 0.05 * len(alerts)), "basis": basis}


def score_zeek(zeek_result: dict | None, has_beacon: bool = False) -> dict:
    """zeek_result=None means Zeek was not run. Zeek is descriptive, not
    judgmental — it never assigns severity itself — so its score is
    deliberately modest even with many anomalies; it's meant to corroborate,
    not to independently declare high risk."""
    if zeek_result is None:
        return {"score": None, "confidence": 0.0, "basis": []}
    weird = zeek_result.get("weird_count", 0) or 0
    score = min(100.0, weird * 4 + (20 if has_beacon else 0))
    basis = [f"{weird} protocol anomal{'y' if weird==1 else 'ies'} (weird.log)"]
    if has_beacon:
        basis.append("connection pattern corroborates a periodic/beacon-shaped flow")
    return {"score": round(score, 1), "confidence": 0.5, "basis": basis}


def score_ml(custom_alerts: list | None) -> dict:
    """The custom engine's overall contribution to fusion — reported as
    "ml_score" to match the project's agreed JSON schema, but it covers all
    13 custom detectors, not only the two ML/behavioural ones. Rationale:
    the other 11 detectors (port scan, brute force, web attacks, exfil,
    ARP spoof, cleartext creds, pentest-tool fingerprinting, ICMP
    flood/shell payloads) are real independent evidence too — folding only
    the ML/beacon alerts in here would make a capture full of, say, SQLi and
    exfil findings contribute *nothing* to the final score just because
    Isolation Forest didn't happen to also fire on it.

    Two layers, taking the max (not the sum, to avoid double-counting the
    same underlying alerts twice within this one engine):
      * `base` — the same saturating severity curve used for Suricata,
        applied across every custom-engine alert.
      * `boost` — a stronger, more confident signal specifically when the
        true behavioural detectors (Isolation Forest, the CV-based C2
        beacon check) fire, since those are evidence no signature/rule
        anticipated — worth surfacing more prominently than a generic
        severity count.
    """
    alerts = custom_alerts
    if alerts is None:
        return {"score": None, "confidence": 0.0, "basis": []}
    if not alerts:
        return {"score": 0.0, "confidence": 0.5, "basis": ["Custom engine ran; no alerts"]}

    raw = sum(SEV_PTS.get(a.get("severity", "LOW"), 0) for a in alerts)
    base = 100.0 * (1 - math.exp(-raw / 120.0))
    basis = [f"{len(alerts)} custom-engine alert(s) (behavioural/heuristic base score)"]

    ml_alerts = [a for a in alerts if "ML Anomaly" in a.get("type", "")]
    beacon_alerts = [a for a in alerts if "Beacon" in a.get("type", "")]
    boost = 0.0
    if ml_alerts:
        raw_scores = [a.get("score", 0.0) for a in ml_alerts if isinstance(a.get("score"), (int, float))]
        if raw_scores:
            worst = min(raw_scores)  # IsolationForest: more negative = more anomalous
            boost = max(boost, max(0.0, min(100.0, (-worst) * 200)))
            basis.append(f"{len(ml_alerts)} statistical outlier(s), worst Isolation Forest score {worst:.3f}")
    if beacon_alerts:
        jitters = [a.get("jitter_pct", 100) for a in beacon_alerts]
        best_jitter = min(jitters)
        boost = max(boost, max(0.0, min(100.0, 100 - best_jitter * 3)))
        basis.append(f"{len(beacon_alerts)} beaconing pattern(s), tightest jitter {best_jitter}%")

    score = max(base, boost)
    confidence = 0.9 if (ml_alerts or beacon_alerts) else 0.55
    return {"score": round(score, 1), "confidence": confidence, "basis": basis}


def score_ti(ips: list, lookup_fn) -> dict:
    """lookup_fn(ip) -> {"ip":.., "is_malicious": bool, "confidence": 0-100,
    "summary": "..."} or None (threat_intel.lookup_combined's shape). Any
    exception, missing key, or lack of a lookup function all mean the same
    thing here: no threat-intel evidence available — score stays None,
    never 0. Only IPs the lookup itself judges "malicious" (a threshold
    defined once in threat_intel.is_malicious, not here) count towards the
    score — a technically-nonzero-but-negligible reputation result is not a
    finding. `ips` is expected to already be the "important" subset
    (risk_engine._flagged_ips restricts this to CRITICAL/HIGH alert IPs)."""
    if not lookup_fn or not ips:
        return {"score": None, "confidence": 0.0, "basis": [], "ips": []}
    hits = []
    for ip in ips:
        try:
            r = lookup_fn(ip)
        except Exception:
            r = None
        if r and r.get("is_malicious"):
            hits.append(r)
    if not hits:
        return {"score": None, "confidence": 0.0, "basis": ["No malicious threat-intel evidence found"], "ips": []}
    hits.sort(key=lambda h: h.get("confidence", 0), reverse=True)
    best = hits[0]["confidence"]
    basis = [f"{h['ip']}: {h.get('summary') or 'flagged malicious'}" for h in hits]
    return {"score": float(best), "confidence": 0.85, "basis": basis, "ips": hits}


# ── Fusion ───────────────────────────────────────────────────────────────────

def fuse(component_scores: dict, weights: dict | None = None) -> dict:
    """component_scores: {"suricata": {...}, "zeek": {...}, "ml": {...}, "ti": {...}}
    each value from the score_* functions above. Renormalizes over only the
    engines whose score is not None."""
    weights = weights or load_weights()
    num = den = 0.0
    used = {}
    for key, comp in component_scores.items():
        score = comp.get("score") if comp else None
        w = weights.get(key, 0.0)
        if score is not None:
            num += score * w
            den += w
            used[key] = w
    final = round(num / den, 1) if den > 0 else None
    return {"final_score": final, "risk_level": classify(final), "weights_used": used}


# ── Duplicate-evidence handling ─────────────────────────────────────────────

def _ip_only(addr: str | None) -> str:
    """Strips a trailing ':port' from an IPv4 'ip:port' string (the format
    kali_bridge.py's Suricata alerts use). Left untouched for bare IPs and
    IPv6 (which contains multiple colons) — never naively .split(':')."""
    if not addr:
        return addr
    return addr.rsplit(":", 1)[0] if addr.count(":") == 1 else addr


def dedupe_suricata(custom_alerts: list | None, suricata_alerts: list | None) -> list:
    """Drops a Suricata alert if the same (source, destination) IP pair
    already has an equal-or-higher-severity custom-engine alert, so the same
    underlying flow isn't counted twice toward the fused score.

    Limitation, documented rather than hidden: matched on IP pair only,
    because neither engine's alerts currently carry a shared flow/session ID
    or a per-alert timestamp precise enough for full 5-tuple+time
    correlation. Good enough to catch the common case (both engines flag the
    same obvious flow); not a substitute for real session correlation."""
    custom_best = {}
    for a in (custom_alerts or []):
        pair = (a.get("source"), a.get("destination"))
        rank = SEV_RANK.get(a.get("severity"), 0)
        if pair not in custom_best or rank > custom_best[pair]:
            custom_best[pair] = rank

    out = []
    for a in (suricata_alerts or []):
        pair = (_ip_only(a.get("source")), _ip_only(a.get("destination")))
        rank = SEV_RANK.get(a.get("severity"), 0)
        if pair in custom_best and custom_best[pair] >= rank:
            continue
        out.append(a)
    return out


# ── Supporting evidence extraction ──────────────────────────────────────────

def _has_beacon(alerts: list | None) -> bool:
    return any("Beacon" in a.get("type", "") for a in (alerts or []))


def c2_indicators(custom_alerts: list | None) -> list:
    out = set()
    for a in (custom_alerts or []):
        t = a.get("type", "")
        if "Beacon" in t:
            out.add("periodic communication / regular-interval callbacks")
        if "Exfil" in t and "ICMP" not in t:
            out.add("bulk outbound data transfer")
        if "DNS Tunnel" in t:
            out.add("anomalous DNS query volume/length (possible tunneling)")
        if "ICMP" in t and "Exfil" in t:
            out.add("oversized ICMP payloads (possible covert channel)")
    return sorted(out)


def mitre_techniques(custom_alerts: list | None, suricata_alerts: list | None) -> list:
    """Returns [{"id": "T1190", "name": "Exploit Public-Facing Application"}, ...] —
    NEVER bare ID strings. A bare ID sent to the LLM gives a small local
    model nothing to work with except its own (unreliable) memory of what
    that ID means, which is exactly how it ends up inventing a wrong
    technique name. Including the name we already computed removes any
    reason for the model to guess."""
    techs = {}
    for a in (custom_alerts or []) + (suricata_alerts or []):
        tid = a.get("mitre_technique_id")
        if tid and tid not in techs:
            techs[tid] = {"id": tid, "name": a.get("mitre_technique") or "Unknown"}
    return [techs[k] for k in sorted(techs)]


def _flagged_ips(custom_alerts: list | None, suricata_alerts: list | None) -> list:
    ips = set()
    for a in (custom_alerts or []):
        if a.get("severity") in ("CRITICAL", "HIGH"):
            for k in ("source", "destination", "target"):
                v = a.get(k)
                if isinstance(v, str):
                    ips.add(v)
    for a in (suricata_alerts or []):
        if a.get("severity") in ("CRITICAL", "HIGH"):
            for k in ("source", "destination"):
                v = _ip_only(a.get(k))
                if v:
                    ips.add(v)
    public_ips = []
    for ip in ips:
        try:
            if not ipaddress.ip_address(ip).is_private:
                public_ips.append(ip)
        except ValueError:
            pass
    return public_ips


# ── Top-level orchestration ─────────────────────────────────────────────────

def compute_full_risk(analysis: dict | None, suricata: dict | None, zeek: dict | None,
                       ti_lookup=None) -> dict:
    """The single entry point server.py calls. Each of analysis/suricata/zeek
    may be None (that engine wasn't run for this file) — every downstream
    function handles that explicitly rather than crashing or assuming 0."""
    custom_alerts = analysis.get("alerts") if analysis else None
    suricata_alerts_raw = suricata.get("alerts") if suricata else None
    suricata_alerts_scored = dedupe_suricata(custom_alerts, suricata_alerts_raw) if suricata is not None else None

    su = score_suricata(suricata_alerts_scored)
    ze = score_zeek(zeek, has_beacon=_has_beacon(custom_alerts))
    ml = score_ml(custom_alerts)
    ips = _flagged_ips(custom_alerts, suricata_alerts_raw)
    ti = score_ti(ips, ti_lookup)

    fused = fuse({"suricata": su, "zeek": ze, "ml": ml, "ti": ti})

    return {
        "suricata_score": su["score"],
        "zeek_score": ze["score"],
        "ml_score": ml["score"],
        "threat_intel_score": ti["score"],
        "final_risk_score": fused["final_score"],
        "risk_level": fused["risk_level"],
        "weights_used": fused["weights_used"],
        "confidence": {
            "suricata": su["confidence"], "zeek": ze["confidence"],
            "ml": ml["confidence"], "threat_intel": ti["confidence"],
        },
        "evidence": {
            "suricata": su["basis"], "zeek": ze["basis"],
            "ml": ml["basis"], "threat_intel": ti["basis"],
        },
        "c2_indicators": c2_indicators(custom_alerts),
        "mitre_techniques": mitre_techniques(custom_alerts, suricata_alerts_raw),
        "threat_intel_ips": ti["ips"],
    }
