"""
Local, file-backed storage for API keys entered through the Settings page —
the alternative to setting environment variables before the server starts.

Deliberately simple: one JSON file next to the app, read/written whole each
time (this app is single-user and single-process, so there is no concurrent-
writer problem to solve). `api_keys.json` is in .gitignore — never committed.
"""
import json
import logging
import os
import threading

logger = logging.getLogger("pcap-engine.config_store")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_FILE = os.path.join(BASE_DIR, "api_keys.json")

_lock = threading.Lock()

KNOWN_KEYS = ("ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY")


def _read_all() -> dict:
    if not os.path.exists(KEYS_FILE):
        return {}
    try:
        with open(KEYS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.warning("Could not read %s (non-fatal, treating as empty): %s", KEYS_FILE, exc)
        return {}


def _write_all(data: dict) -> None:
    with open(KEYS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def get_key(name: str) -> str:
    """Returns the stored value for `name` (e.g. "ABUSEIPDB_API_KEY"), or ""
    if nothing has been saved for it. Callers fall back to the environment
    variable themselves — this module only knows about the file."""
    with _lock:
        return _read_all().get(name, "")


def set_key(name: str, value: str) -> None:
    if name not in KNOWN_KEYS:
        raise ValueError(f"Unknown key name: {name}")
    with _lock:
        data = _read_all()
        data[name] = value.strip()
        _write_all(data)
    # Take effect immediately — no server restart needed.
    try:
        import threat_intel
        threat_intel.reload_keys()
    except Exception as exc:
        logger.warning("Could not hot-reload threat_intel keys (non-fatal): %s", exc)


def masked(value: str) -> str:
    """e.g. 'sk-ab34...9f21' — enough to recognise which key is saved
    without ever sending the full secret back to the browser."""
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"
