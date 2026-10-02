"""
Threat-intelligence lookups (AbuseIPDB + VirusTotal) — supporting evidence
only, never the sole reason anything is declared malicious. Every failure
mode (no API key, network error, timeout, rate limit, malformed response)
resolves to the same thing from the caller's point of view: `None`, meaning
"no evidence available", never an exception and never a false "0 = clean".

Two providers, chosen for this project because:
  * AbuseIPDB — simplest free-tier API for IP reputation (a single GET,
    no bulk feed/DB to sync), 1,000 requests/day, returns an
    already-normalized 0-100 "abuse confidence score".
  * VirusTotal — a second, independent judgement (a per-vendor detection
    count rather than a community-report score), which is exactly the
    point of having two sources: they can corroborate or disagree, and an
    IP flagged by both is far more likely to be a genuine finding than one
    flagged by either alone. Free tier is a much tighter 4 req/min /
    500/day, handled below with an in-process rate limiter rather than
    letting a burst silently degrade into 429s (which would otherwise look
    identical to "no evidence" from the caller's side).

`lookup_combined()` is the one function the rest of the app should call —
it queries whichever provider(s) are configured and applies a single,
documented "is this IP actually malicious" threshold (see `is_malicious`)
so a technically-nonzero-but-negligible reputation score never gets
surfaced as if it were a finding. Adding a third provider later only means
adding another `lookup_ip_*`-shaped function and one line in
`lookup_combined` — this module never assumes there are exactly two.
"""
import json
import logging
import os
import sqlite3
import time
from collections import deque

import requests

logger = logging.getLogger("pcap-engine.threat_intel")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_DB = os.path.join(BASE_DIR, "ti_cache.db")
CACHE_TTL_SECONDS = 24 * 60 * 60  # 24h — reputation data doesn't change minute to minute
REQUEST_TIMEOUT = 5  # seconds — never let a slow/hung API stall the dashboard

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

# Malicious thresholds — the single definition of "actually malicious" used
# by both the fusion score and the UI's itemized list, so the two can never
# disagree with each other.
ABUSEIPDB_MALICIOUS_AT = 25   # AbuseIPDB's own guidance treats >25% as noteworthy
VIRUSTOTAL_MALICIOUS_AT = 2   # >=2 vendors, to avoid one stray false positive

# VirusTotal free tier: 4 requests/minute. Tracks recent call timestamps and
# sleeps just enough to stay under the limit rather than bursting into 429s
# (which would otherwise silently look like "no evidence" to callers).
_VT_RATE_WINDOW = 60.0
_VT_RATE_MAX = 4
_vt_call_times = deque()


def _load_key(env_var: str) -> str:
    """UI-saved keys (via config_store) take priority; the environment
    variable is the fallback for anyone who prefers setting it that way
    without touching the settings page."""
    try:
        import config_store
        stored = config_store.get_key(env_var)
        if stored:
            return stored.strip()
    except Exception as exc:
        logger.warning("config_store unavailable, using environment only: %s", exc)
    return os.environ.get(env_var, "").strip()


ABUSEIPDB_API_KEY = _load_key("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = _load_key("VIRUSTOTAL_API_KEY")


def reload_keys() -> None:
    """Re-reads both keys from config_store/environment. Called by
    config_store.set_key() right after a save, so a key entered in the
    Settings page takes effect immediately — no server restart needed."""
    global ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY
    ABUSEIPDB_API_KEY = _load_key("ABUSEIPDB_API_KEY")
    VIRUSTOTAL_API_KEY = _load_key("VIRUSTOTAL_API_KEY")


def is_configured(source: str | None = None) -> bool:
    if source == "abuseipdb":
        return bool(ABUSEIPDB_API_KEY)
    if source == "virustotal":
        return bool(VIRUSTOTAL_API_KEY)
    return bool(ABUSEIPDB_API_KEY) or bool(VIRUSTOTAL_API_KEY)


# ── Cache (shared table, keyed by (ip, source) so providers never collide) ──

def _cache_get(ip: str, source: str) -> dict | None:
    try:
        conn = sqlite3.connect(CACHE_DB, timeout=2)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ti_cache (ip TEXT, source TEXT, data TEXT, "
            "fetched_at REAL, PRIMARY KEY (ip, source))"
        )
        row = conn.execute(
            "SELECT data, fetched_at FROM ti_cache WHERE ip=? AND source=?", (ip, source)
        ).fetchone()
        conn.close()
        if not row:
            return None
        data, fetched_at = row
        if time.time() - fetched_at > CACHE_TTL_SECONDS:
            return None
        return json.loads(data)
    except Exception as exc:
        logger.warning("TI cache read failed (non-fatal): %s", exc)
        return None


def _cache_put(ip: str, source: str, data: dict) -> None:
    try:
        conn = sqlite3.connect(CACHE_DB, timeout=2)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ti_cache (ip TEXT, source TEXT, data TEXT, "
            "fetched_at REAL, PRIMARY KEY (ip, source))"
        )
        conn.execute(
            "INSERT OR REPLACE INTO ti_cache (ip, source, data, fetched_at) VALUES (?, ?, ?, ?)",
            (ip, source, json.dumps(data), time.time()),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        logger.warning("TI cache write failed (non-fatal): %s", exc)


# ── AbuseIPDB ────────────────────────────────────────────────────────────────

def lookup_ip(ip: str) -> dict | None:
    """Returns {"abuse_confidence": 0-100, "country": "..", "total_reports": n,
    "cached": bool} or None if unavailable for any reason. Never raises."""
    if not ABUSEIPDB_API_KEY:
        return None

    cached = _cache_get(ip, "abuseipdb")
    if cached is not None:
        cached = dict(cached)
        cached["cached"] = True
        return cached

    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            logger.warning("AbuseIPDB returned HTTP %s for %s", resp.status_code, ip)
            return None
        data = resp.json().get("data", {})
        result = {
            "abuse_confidence": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode"),
            "total_reports": data.get("totalReports", 0),
            "cached": False,
        }
        _cache_put(ip, "abuseipdb", result)
        return result
    except requests.RequestException as exc:
        logger.warning("AbuseIPDB lookup failed for %s (non-fatal): %s", ip, exc)
        return None
    except Exception as exc:
        logger.warning("AbuseIPDB lookup unexpected error for %s (non-fatal): %s", ip, exc)
        return None


# ── VirusTotal ───────────────────────────────────────────────────────────────

def _vt_throttle() -> None:
    """Blocks just long enough to keep us under 4 requests/minute. A no-op
    once fewer than 4 calls have happened in the trailing window."""
    now = time.time()
    while _vt_call_times and now - _vt_call_times[0] > _VT_RATE_WINDOW:
        _vt_call_times.popleft()
    if len(_vt_call_times) >= _VT_RATE_MAX:
        wait = _VT_RATE_WINDOW - (now - _vt_call_times[0]) + 0.1
        if wait > 0:
            logger.info("VirusTotal rate limit: waiting %.1fs", wait)
            time.sleep(wait)
    _vt_call_times.append(time.time())


def lookup_ip_virustotal(ip: str) -> dict | None:
    """Returns {"malicious": n, "suspicious": n, "harmless": n,
    "total_engines": n, "cached": bool} or None if unavailable for any
    reason. Never raises."""
    if not VIRUSTOTAL_API_KEY:
        return None

    cached = _cache_get(ip, "virustotal")
    if cached is not None:
        cached = dict(cached)
        cached["cached"] = True
        return cached

    try:
        _vt_throttle()
        resp = requests.get(
            VIRUSTOTAL_URL.format(ip=ip),
            headers={"x-apikey": VIRUSTOTAL_API_KEY, "Accept": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            logger.warning("VirusTotal returned HTTP %s for %s", resp.status_code, ip)
            return None
        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected + stats.get("timeout", 0)
        result = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "total_engines": total,
            "cached": False,
        }
        _cache_put(ip, "virustotal", result)
        return result
    except requests.RequestException as exc:
        logger.warning("VirusTotal lookup failed for %s (non-fatal): %s", ip, exc)
        return None
    except Exception as exc:
        logger.warning("VirusTotal lookup unexpected error for %s (non-fatal): %s", ip, exc)
        return None


# ── Combined verdict ─────────────────────────────────────────────────────────

def is_malicious(result: dict | None, source: str) -> bool:
    """The one place "actually malicious" is defined, so the fusion score
    and the UI's itemized list can never disagree with each other."""
    if not result:
        return False
    if source == "abuseipdb":
        return result.get("abuse_confidence", 0) >= ABUSEIPDB_MALICIOUS_AT
    if source == "virustotal":
        return result.get("malicious", 0) >= VIRUSTOTAL_MALICIOUS_AT
    return False


def lookup_combined(ip: str) -> dict | None:
    """Queries whichever provider(s) are configured and returns one merged
    verdict:
      {"ip": ip, "abuseipdb": {...}|None, "virustotal": {...}|None,
       "is_malicious": bool, "confidence": 0-100, "summary": "..."}
    Returns None only if neither provider is configured at all — if a
    provider is configured but the IP comes back clean, that is a real
    (negative) result, not a missing one, so this still returns a dict with
    is_malicious=False rather than None."""
    if not is_configured():
        return None

    ab = lookup_ip(ip) if ABUSEIPDB_API_KEY else None
    vt = lookup_ip_virustotal(ip) if VIRUSTOTAL_API_KEY else None

    ab_hit = is_malicious(ab, "abuseipdb")
    vt_hit = is_malicious(vt, "virustotal")

    confidence = 0.0
    parts = []
    if ab is not None:
        confidence = max(confidence, float(ab.get("abuse_confidence", 0)))
        if ab_hit:
            parts.append(f"AbuseIPDB {ab['abuse_confidence']}% confidence")
    if vt is not None:
        total = vt.get("total_engines") or 1
        vt_score = min(100.0, (vt.get("malicious", 0) / total) * 100 * 2)
        confidence = max(confidence, vt_score)
        if vt_hit:
            parts.append(f"VirusTotal {vt['malicious']}/{total} engines flagged")

    return {
        "ip": ip,
        "abuseipdb": ab,
        "virustotal": vt,
        "is_malicious": ab_hit or vt_hit,
        "confidence": round(confidence, 1),
        "summary": " · ".join(parts) if parts else None,
    }
