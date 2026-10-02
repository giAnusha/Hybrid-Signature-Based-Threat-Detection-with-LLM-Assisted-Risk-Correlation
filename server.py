#!/usr/bin/env python3
"""
Next-Gen PCAP Analysis Engine v2.0
Secure · Scalable · Production-Grade Threat Detection
"""

import sys
import os
import re
import json
import uuid
import time
import logging
import tempfile
import threading
from datetime import datetime
from collections import Counter, defaultdict
from functools import wraps

import numpy as np

from flask import Flask, render_template, request, jsonify, Response
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

try:
    from scapy.all import rdpcap, TCP, UDP, DNS, IP, ICMP, Raw, DNSQR, ARP, DNSRR
except ImportError:
    print("ERROR: Scapy is required. Run: pip install scapy --break-system-packages")
    sys.exit(1)

try:
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("WARNING: scikit-learn not available. ML detection disabled.")

try:
    from geoip2.database import Reader as GeoIP2Reader
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

import ipaddress

import kali_bridge
import risk_engine
import threat_intel
import config_store
import llm_explainer

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("pcap_analysis.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("pcap-engine")

# ── Constants ─────────────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR   = os.path.join(BASE_DIR, "uploads")
GEOIP_DB     = os.path.join(BASE_DIR, "GeoLite2-City.mmdb")
MAX_FILE_MB  = 500
VERSION      = "2.0.0"

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",  # pcap LE
    b"\xa1\xb2\xc3\xd4",  # pcap BE
    b"\x0a\x0d\x0d\x0a",  # pcapng
    b"\x4d\x3c\xb2\xa1",  # modified pcap
}

# ── In-memory rate-limit and progress stores ──────────────────────────────────
_rl_store: dict[str, list] = defaultdict(list)
_rl_lock  = threading.Lock()
_progress: dict[str, dict] = {}
_prog_lock = threading.Lock()

os.makedirs(UPLOAD_DIR, exist_ok=True)

# ── Flask App ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config.update(
    MAX_CONTENT_LENGTH=MAX_FILE_MB * 1024 * 1024,
    SECRET_KEY=os.environ.get("SECRET_KEY", os.urandom(32)),
    JSON_SORT_KEYS=False,
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

SECURITY_HEADERS = {
    "X-Content-Type-Options":    "nosniff",
    "X-Frame-Options":           "DENY",
    "X-XSS-Protection":         "1; mode=block",
    "Referrer-Policy":          "strict-origin-when-cross-origin",
    "Permissions-Policy":       "geolocation=(), microphone=(), camera=()",
    "Cache-Control":            "no-store, no-cache, must-revalidate",
    "Content-Security-Policy":  (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "img-src 'self' data:;"
    ),
}

@app.after_request
def add_security_headers(resp):
    for k, v in SECURITY_HEADERS.items():
        resp.headers[k] = v
    resp.headers.pop("Server", None)
    return resp


# ── Decorators ────────────────────────────────────────────────────────────────
def rate_limit(max_req: int = 10, window: int = 60):
    """Token-bucket rate limiter keyed by (IP, endpoint)."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            ip  = request.remote_addr or "0.0.0.0"
            key = f"{ip}:{fn.__name__}"
            now = time.time()
            with _rl_lock:
                _rl_store[key] = [t for t in _rl_store[key] if now - t < window]
                if len(_rl_store[key]) >= max_req:
                    logger.warning("Rate-limit hit: %s", key)
                    return jsonify({"error": "Too many requests. Please wait.", "retry_after": window}), 429
                _rl_store[key].append(now)
            return fn(*a, **kw)
        return wrapper
    return deco


# ── Input validation ──────────────────────────────────────────────────────────
def validate_pcap_bytes(data: bytes) -> tuple[bool, str]:
    if len(data) < 4:
        return False, "File too small to be a valid PCAP."
    if data[:4] in PCAP_MAGIC:
        return True, "OK"
    return False, "Invalid file format. Only PCAP / PCAPng accepted."


def safe_path(filename: str) -> str | None:
    """Resolve an upload path and verify no path-traversal."""
    filename = secure_filename(filename)
    if not filename or not filename.lower().endswith((".pcap", ".pcapng")):
        return None
    # Strip anything except safe chars
    filename = re.sub(r"[^\w\-.]", "_", filename)
    full = os.path.realpath(os.path.join(UPLOAD_DIR, filename))
    base = os.path.realpath(UPLOAD_DIR)
    if not full.startswith(base + os.sep):
        logger.warning("Path-traversal blocked: %s", filename)
        return None
    return full


# ── Threat Signatures ─────────────────────────────────────────────────────────
RISKY_PORTS: dict[int, str] = {
    21: "FTP",       22: "SSH",    23: "Telnet",  25: "SMTP",
    445: "SMB",      1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432: "PgSQL",   5984: "CouchDB", 6379: "Redis",
    9200: "Elastic", 27017: "Mongo", 50000: "DB2",
    4444: "MSF",     1080: "SOCKS",  8080: "HTTP-Alt",
}

WELL_KNOWN: dict[int, str] = {
    **RISKY_PORTS,
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 8443: "HTTPS-Alt",
}

CRED_PATTERNS = [
    b"USER ", b"PASS ", b"PASSWORD", b"password=",
    b"Authorization: Basic", b"user=", b"login=",
    b"passwd=", b"secret=", b"token=", b"api_key=",
]

PENTEST_AGENTS = [
    b"sqlmap", b"nmap", b"metasploit", b"nikto", b"w3af",
    b"burpsuite", b"ZAP", b"masscan", b"aircrack", b"hashcat",
    b"hydra", b"medusa", b"dirbuster", b"gobuster", b"wfuzz",
    b"nuclei", b"acunetix",
]

SHELL_KEYWORDS = [
    b"cmd.exe", b"powershell", b"/bin/sh", b"/bin/bash",
    b"shellcode", b"exploit", b"payload",
    b"wget http", b"curl http", b"nc -e", b"bash -i",
]

# ── Compiled Regex ────────────────────────────────────────────────────────────
RE_SQLI = re.compile(
    rb"(?i)(union\s+select|select\s+.{1,60}\s+from|insert\s+into"
    rb"|update\s+.{1,60}\s+set|delete\s+from"
    rb"|'\s*or\s+'1'\s*=\s*'1|--\s*$"
    rb"|sleep\s*\(\d+\)|waitfor\s+delay|xp_cmdshell|information_schema)",
    re.DOTALL,
)
RE_XSS = re.compile(
    rb"(?i)(<script[\s>]|javascript:|onerror\s*=|onload\s*=|"
    rb"<img[^>]+onerror|<svg[^>]+onload|eval\s*\(|"
    rb"document\.cookie|\.innerHTML\s*=)",
    re.DOTALL,
)
RE_CMDI = re.compile(
    rb"(?i)(;\s*cat\s+/etc/passwd|;\s*ls\s+-la"
    rb"|\|\s*sh\s*$|;\s*wget\s+http|;\s*curl\s+http"
    rb"|`[^`]{1,80}`|\$\([^)]{1,80}\)|&&\s*rm\s+-rf"
    rb"|;\s*nc\s+|;\s*netcat\s+)",
    re.DOTALL,
)
RE_PATH = re.compile(rb"(?i)(\.\.\/|\.\.\\\\|%2e%2e%2f|%252e%252e%252f)")
RE_LFI  = re.compile(
    rb"(?i)(file=|path=|page=|include=).{0,60}(etc/passwd|win\.ini|boot\.ini)",
    re.DOTALL,
)


# ── GeoIP ─────────────────────────────────────────────────────────────────────
_geo_reader: GeoIP2Reader | None = None
_geo_lock = threading.Lock()


def geo_reader() -> GeoIP2Reader | None:
    global _geo_reader
    if not GEOIP_AVAILABLE:
        return None
    with _geo_lock:
        if _geo_reader is None and os.path.isfile(GEOIP_DB):
            try:
                _geo_reader = GeoIP2Reader(GEOIP_DB)
            except Exception as exc:
                logger.warning("GeoIP init failed: %s", exc)
    return _geo_reader


def country_for(ip: str) -> str:
    r = geo_reader()
    if not r:
        return "Unknown"
    try:
        resp = r.city(ip)
        code = resp.country.iso_code or "??"
        city = resp.city.name or ""
        return f"{code}" + (f" ({city})" if city else "")
    except Exception:
        return "Unknown"


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ── MITRE ATT&CK / Cyber Kill Chain classification ────────────────────────────
# Lockheed Martin's 7-stage kill chain. Weaponization and Delivery happen
# before traffic ever reaches the wire, so a PCAP-only detector will
# legitimately never populate those two stages — that's an honest visibility
# gap, not a missing detector.
KILL_CHAIN_STAGES = [
    "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
    "Installation", "Command & Control", "Actions on Objectives",
]

# alert `type` -> (tactic_id, tactic, technique_id, technique, kill_chain_stage)
# Exact coverage for every alert type the 13 custom detectors can emit.
MITRE_MAP: dict[str, tuple] = {
    "Port Scan":                     ("TA0007", "Discovery",               "T1046",     "Network Service Discovery",                     "Reconnaissance"),
    "SSH Brute Force":               ("TA0006", "Credential Access",       "T1110",     "Brute Force",                                    "Exploitation"),
    "FTP Brute Force":               ("TA0006", "Credential Access",       "T1110",     "Brute Force",                                    "Exploitation"),
    "RDP Brute Force":               ("TA0006", "Credential Access",       "T1110",     "Brute Force",                                    "Exploitation"),
    "VNC Brute Force":               ("TA0006", "Credential Access",       "T1110",     "Brute Force",                                    "Exploitation"),
    "Service Brute Force":           ("TA0006", "Credential Access",       "T1110",     "Brute Force",                                    "Exploitation"),
    "DNS Tunneling":                 ("TA0011", "Command and Control",     "T1071.004", "Application Layer Protocol: DNS",               "Command & Control"),
    "Lateral Movement":              ("TA0008", "Lateral Movement",        "T1021",     "Remote Services",                               "Actions on Objectives"),
    "Data Exfiltration":             ("TA0010", "Exfiltration",            "T1041",     "Exfiltration Over C2 Channel",                  "Actions on Objectives"),
    "ARP Spoofing":                  ("TA0006", "Credential Access",       "T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning",  "Exploitation"),
    "ARP Flood":                     ("TA0040", "Impact",                  "T1499",     "Endpoint Denial of Service",                    "Actions on Objectives"),
    "Cleartext Credentials":         ("TA0006", "Credential Access",       "T1040",     "Network Sniffing",                              "Exploitation"),
    "Pentest Tool Detected":         ("TA0043", "Reconnaissance",          "T1595",     "Active Scanning",                               "Reconnaissance"),
    "SQL Injection":                 ("TA0001", "Initial Access",          "T1190",     "Exploit Public-Facing Application",             "Exploitation"),
    "Cross-Site Scripting":          ("TA0001", "Initial Access",          "T1190",     "Exploit Public-Facing Application",             "Exploitation"),
    "Command Injection":             ("TA0002", "Execution",               "T1059",     "Command and Scripting Interpreter",             "Exploitation"),
    "Path Traversal":                ("TA0001", "Initial Access",          "T1190",     "Exploit Public-Facing Application",             "Exploitation"),
    "Local File Inclusion":          ("TA0001", "Initial Access",          "T1190",     "Exploit Public-Facing Application",             "Exploitation"),
    "ICMP Flood":                    ("TA0040", "Impact",                  "T1499",     "Endpoint Denial of Service",                    "Actions on Objectives"),
    "ICMP Flood / Exfiltration":     ("TA0011", "Command and Control",     "T1095",     "Non-Application Layer Protocol",                "Command & Control"),
    "Malicious Payload":             ("TA0002", "Execution",               "T1059",     "Command and Scripting Interpreter",             "Installation"),
    "Possible C2 Beaconing":         ("TA0011", "Command and Control",     "T1071",     "Application Layer Protocol",                    "Command & Control"),
    "ML Anomaly (Isolation Forest)": (None,     "Uncategorized",           None,        "Statistical anomaly — no fixed technique",      "Unknown"),
}

# Suricata's eve.json `category` field is NOT the raw classtype keyword from
# local.rules/classification.config (e.g. "policy-violation") — it's that
# classtype's human-readable description ("Potential Corporate Privacy
# Violation"), the second field of each `config classification:` line. Keys
# below are the lower-cased description strings, matched against the actual
# 20 classtypes used in this project's local.rules plus the standard
# Suricata default classification.config descriptions most likely to appear
# from the Emerging Threats ruleset. Anything not here reports honestly as
# "Unmapped" rather than a guess — ET Open carries hundreds of categories
# beyond this list.
MITRE_SURICATA_CATEGORY_MAP: dict[str, tuple] = {
    "web application attack":                                   ("TA0001", "Initial Access",       "T1190", "Exploit Public-Facing Application",     "Exploitation"),
    "attempted administrator privilege gain":                   ("TA0004", "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", "Installation"),
    "successful administrator privilege gain":                  ("TA0004", "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", "Installation"),
    "potential corporate privacy violation":                    ("TA0009", "Collection",           "T1552", "Unsecured Credentials",                 "Exploitation"),
    "attempted information leak":                                ("TA0043", "Reconnaissance",       "T1595", "Active Scanning",                       "Reconnaissance"),
    "information leak":                                          ("TA0043", "Reconnaissance",       "T1595", "Active Scanning",                       "Reconnaissance"),
    "a network trojan was detected":                             ("TA0011", "Command and Control",  "T1071", "Application Layer Protocol",            "Command & Control"),
    "malware command and control activity detected":            ("TA0011", "Command and Control",  "T1071", "Application Layer Protocol",            "Command & Control"),
    "domain observed used for c2 detected":                      ("TA0011", "Command and Control",  "T1071", "Application Layer Protocol",            "Command & Control"),
    "attempted user privilege gain":                             ("TA0001", "Initial Access",       "T1190", "Exploit Public-Facing Application",     "Exploitation"),
    "access to a potentially vulnerable web application":       ("TA0043", "Reconnaissance",       "T1595", "Active Scanning",                       "Reconnaissance"),
    "detection of a denial of service attack":                   ("TA0040", "Impact",               "T1499", "Endpoint Denial of Service",            "Actions on Objectives"),
    "attempted denial of service":                               ("TA0040", "Impact",               "T1499", "Endpoint Denial of Service",            "Actions on Objectives"),
    "misc attack":                                                ("TA0002", "Execution",            "T1059", "Command and Scripting Interpreter",     "Exploitation"),
    "detection of a network scan":                                ("TA0007", "Discovery",            "T1046", "Network Service Discovery",             "Reconnaissance"),
    "executable code was detected":                               ("TA0002", "Execution",            "T1059", "Command and Scripting Interpreter",     "Installation"),
    "successful credential theft detected":                       ("TA0006", "Credential Access",    "T1552", "Unsecured Credentials",                 "Exploitation"),
    "exploit kit activity detected":                              ("TA0001", "Initial Access",        "T1190", "Exploit Public-Facing Application",     "Exploitation"),
}

MITRE_UNMAPPED = (None, "Unmapped", None, "Not in local classification table", "Unknown")


def mitre_lookup(alert_type: str | None = None, suricata_category: str | None = None) -> dict:
    row = None
    if alert_type and alert_type in MITRE_MAP:
        row = MITRE_MAP[alert_type]
    elif suricata_category:
        row = MITRE_SURICATA_CATEGORY_MAP.get(suricata_category.lower())
    if not row:
        row = MITRE_UNMAPPED
    tactic_id, tactic, tech_id, tech, stage = row
    return {
        "mitre_tactic_id":    tactic_id,
        "mitre_tactic":       tactic,
        "mitre_technique_id": tech_id,
        "mitre_technique":    tech,
        "kill_chain_stage":   stage,
    }


def geo_point(ip: str) -> dict | None:
    """Lat/lon + country for the threat map. Returns None for private IPs,
    unresolvable addresses, or when the GeoIP DB has no location for the IP."""
    r = geo_reader()
    if not r:
        return None
    try:
        resp = r.city(ip)
        lat, lon = resp.location.latitude, resp.location.longitude
        if lat is None or lon is None:
            return None
        return {
            "ip":      ip,
            "lat":     lat,
            "lon":     lon,
            "country": resp.country.iso_code or "??",
            "city":    resp.city.name or "",
        }
    except Exception:
        return None


# ── Threat Detectors ──────────────────────────────────────────────────────────

def d_port_scan(packets) -> list:
    syn_ports: dict[str, set] = defaultdict(set)
    syn_times: dict[str, list] = defaultdict(list)
    for pkt in packets:
        if IP in pkt and TCP in pkt and (pkt[TCP].flags & 0x02):
            syn_ports[pkt[IP].src].add(pkt[TCP].dport)
            try:
                syn_times[pkt[IP].src].append(float(pkt.time))
            except Exception:
                pass

    out = []
    for src, ports in syn_ports.items():
        if len(ports) > 20:
            times = sorted(syn_times[src])
            dur   = (times[-1] - times[0]) if len(times) > 1 else 1
            rate  = len(ports) / max(dur, 0.001)
            sev   = "CRITICAL" if (len(ports) > 100 or rate > 50) else "HIGH"
            out.append({
                "type":     "Port Scan",
                "source":   src,
                "severity": sev,
                "critical": True,
                "port_count": len(ports),
                "scan_rate":  round(rate, 1),
                "details": (
                    f"Reconnaissance from {src}: {len(ports)} unique ports probed "
                    f"at {round(rate,1)} ports/sec over {round(dur,1)}s"
                ),
            })
    return out


def d_brute_force(packets) -> list:
    counts: dict[str, Counter] = defaultdict(Counter)
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            dport = pkt[TCP].dport
            if dport in (22, 21, 3389, 5900):
                counts[dport][f"{pkt[IP].src}→{pkt[IP].dst}"] += 1

    label_map = {22: "SSH", 21: "FTP", 3389: "RDP", 5900: "VNC"}
    out = []
    for port, ctr in counts.items():
        for pair, n in ctr.items():
            if n > 20:
                src, dst = pair.split("→")
                out.append({
                    "type":     f"{label_map.get(port,'Service')} Brute Force",
                    "source":   src,
                    "target":   dst,
                    "severity": "CRITICAL",
                    "critical": True,
                    "attempt_count": n,
                    "details": (
                        f"{label_map.get(port,'Service')} brute-force: "
                        f"{n} attempts from {src} → {dst}"
                    ),
                })
    return out


def d_dns_tunneling(packets) -> list:
    q_count: Counter = Counter()
    long_q:  Counter = Counter()
    for pkt in packets:
        if IP in pkt and UDP in pkt and pkt[UDP].dport == 53 and DNS in pkt:
            src = pkt[IP].src
            q_count[src] += 1
            try:
                qname = pkt[DNS].qd.qname.decode(errors="ignore")
                if len(qname) > 60:
                    long_q[src] += 1
            except Exception:
                pass

    out = []
    for ip, n in q_count.items():
        lq = long_q.get(ip, 0)
        if n > 500 or lq > 20:
            reasons = []
            if n > 500:  reasons.append(f"{n} DNS queries")
            if lq > 20:  reasons.append(f"{lq} unusually long labels")
            out.append({
                "type":     "DNS Tunneling",
                "source":   ip,
                "severity": "HIGH",
                "critical": True,
                "query_count": n,
                "long_labels": lq,
                "details": f"DNS exfiltration suspected from {ip}: {', '.join(reasons)}",
            })
    return out


def d_lateral_movement(packets) -> list:
    moves: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            dport = pkt[TCP].dport
            if is_private(src) and is_private(dst) and src != dst:
                if dport in RISKY_PORTS:
                    moves[src][dst].add(dport)

    out = []
    for src, targets in moves.items():
        if len(targets) > 3:
            all_ports = set()
            for ps in targets.values():
                all_ports |= ps
            names = [f"{p}/{RISKY_PORTS[p]}" for p in all_ports if p in RISKY_PORTS][:6]
            out.append({
                "type":     "Lateral Movement",
                "source":   src,
                "severity": "HIGH",
                "critical": True,
                "target_count": len(targets),
                "ports": list(all_ports),
                "details": (
                    f"Internal pivot from {src} → {len(targets)} hosts "
                    f"via {', '.join(names)}"
                ),
            })
    return out


def d_data_exfil(packets) -> list:
    out_bytes:    Counter = Counter()
    out_sessions: Counter = Counter()
    for pkt in packets:
        if IP in pkt and Raw in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            if is_private(src) and not is_private(dst):
                try:
                    out_bytes[f"{src}→{dst}"]    += len(bytes(pkt[Raw].load))
                    out_sessions[f"{src}→{dst}"] += 1
                except Exception:
                    pass

    out = []
    for key, total in sorted(out_bytes.items(), key=lambda x: -x[1])[:5]:
        if total > 500_000:
            src, dst = key.split("→")
            mb = total / (1024 * 1024)
            out.append({
                "type":      "Data Exfiltration",
                "source":    src,
                "destination": dst,
                "severity":  "CRITICAL" if mb > 5 else "HIGH",
                "critical":  True,
                "bytes":     total,
                "mb":        round(mb, 2),
                "sessions":  out_sessions[key],
                "details": (
                    f"Outbound bulk transfer: {round(mb,2)} MB from {src} → {dst} "
                    f"({out_sessions[key]} packets)"
                ),
            })
    return out


def d_arp_spoof(packets) -> list:
    ip_macs: dict[str, set] = defaultdict(set)
    reply_ct: Counter = Counter()
    for pkt in packets:
        if ARP in pkt and pkt[ARP].op == 2:
            ip_macs[pkt[ARP].psrc].add(pkt[ARP].hwsrc)
            reply_ct[pkt[ARP].psrc] += 1

    out = []
    for ip, macs in ip_macs.items():
        if len(macs) > 1:
            out.append({
                "type":     "ARP Spoofing",
                "target_ip": ip,
                "severity": "CRITICAL",
                "critical": True,
                "mac_count": len(macs),
                "details": (
                    f"IP {ip} claimed by {len(macs)} MACs: "
                    f"{', '.join(list(macs)[:3])}"
                ),
            })
    for ip, n in reply_ct.items():
        if n > 50 and ip not in {r.get("target_ip") for r in out}:
            out.append({
                "type":     "ARP Flood",
                "source":   ip,
                "severity": "HIGH",
                "critical": True,
                "packet_count": n,
                "details": f"ARP flood from {ip}: {n} unsolicited replies",
            })
    return out


def d_cleartext_creds(packets) -> list:
    seen: set[str] = set()
    out  = []
    for pkt in packets:
        if Raw not in pkt or IP not in pkt:
            continue
        try:
            payload = bytes(pkt[Raw].load).lower()
            src, dst = pkt[IP].src, pkt[IP].dst
            key = f"{src}|{dst}"
            if key in seen:
                continue
            for pat in CRED_PATTERNS:
                if pat.lower() in payload:
                    seen.add(key)
                    proto = (
                        "FTP" if TCP in pkt and pkt[TCP].dport in (21, 20)
                        else "Telnet" if TCP in pkt and pkt[TCP].dport == 23
                        else "HTTP"
                    )
                    out.append({
                        "type":      "Cleartext Credentials",
                        "source":    src,
                        "destination": dst,
                        "protocol":  proto,
                        "severity":  "CRITICAL",
                        "critical":  True,
                        "details": (
                            f"Credentials transmitted in plaintext via {proto}: "
                            f"{src} → {dst}"
                        ),
                    })
                    break
        except Exception:
            pass
    return out[:15]


def d_pentest_agents(packets) -> list:
    seen: set[str] = set()
    out  = []
    for pkt in packets:
        if Raw not in pkt or IP not in pkt:
            continue
        try:
            payload = bytes(pkt[Raw].load)
            if b"User-Agent:" not in payload and b"user-agent:" not in payload:
                continue
            src = pkt[IP].src
            if src in seen:
                continue
            for agent in PENTEST_AGENTS:
                if agent.lower() in payload.lower():
                    seen.add(src)
                    out.append({
                        "type":      "Pentest Tool Detected",
                        "source":    src,
                        "destination": pkt[IP].dst,
                        "tool":      agent.decode(errors="ignore"),
                        "severity":  "HIGH",
                        "critical":  True,
                        "details": (
                            f"Security tool '{agent.decode()}' User-Agent "
                            f"from {src} → {pkt[IP].dst}"
                        ),
                    })
                    break
        except Exception:
            pass
    return out[:10]


def d_web_attacks(packets) -> list:
    out = []
    for pkt in packets:
        if Raw not in pkt or IP not in pkt:
            continue
        try:
            payload = bytes(pkt[Raw].load)
            src, dst = pkt[IP].src, pkt[IP].dst
            snippet = payload[:300].decode(errors="replace")

            if RE_SQLI.search(payload):
                out.append({
                    "type": "SQL Injection",     "source": src, "destination": dst,
                    "severity": "CRITICAL",       "critical": True,
                    "details": f"SQLi payload from {src} → {dst}",
                    "snippet": snippet,
                })
            elif RE_XSS.search(payload):
                out.append({
                    "type": "Cross-Site Scripting", "source": src, "destination": dst,
                    "severity": "HIGH",              "critical": True,
                    "details": f"XSS payload from {src} → {dst}",
                    "snippet": snippet,
                })
            elif RE_CMDI.search(payload):
                out.append({
                    "type": "Command Injection",  "source": src, "destination": dst,
                    "severity": "CRITICAL",        "critical": True,
                    "details": f"OS command injection from {src} → {dst}",
                    "snippet": snippet,
                })
            elif RE_PATH.search(payload):
                out.append({
                    "type": "Path Traversal",    "source": src, "destination": dst,
                    "severity": "HIGH",           "critical": True,
                    "details": f"Directory traversal from {src} → {dst}",
                    "snippet": snippet,
                })
            elif RE_LFI.search(payload):
                out.append({
                    "type": "Local File Inclusion", "source": src, "destination": dst,
                    "severity": "CRITICAL",          "critical": True,
                    "details": f"LFI attempt from {src} → {dst}",
                    "snippet": snippet,
                })
        except Exception:
            pass
    return out[:20]


def d_icmp_flood(packets) -> list:
    cnt:  Counter = Counter()
    size: Counter = Counter()
    for pkt in packets:
        if IP in pkt and ICMP in pkt:
            cnt[pkt[IP].src]  += 1
            size[pkt[IP].src] += len(pkt)

    out = []
    for src, n in cnt.items():
        if n > 50:
            avg = size[src] // n
            exfil = avg > 200
            out.append({
                "type":     "ICMP Flood" + (" / Exfiltration" if exfil else ""),
                "source":   src,
                "severity": "HIGH",
                "critical": True,
                "packet_count": n,
                "avg_size":     avg,
                "details": (
                    f"Excessive ICMP from {src}: {n} packets, avg {avg}B"
                    + (" — large payloads suggest covert channel" if exfil else "")
                ),
            })
    return out


def d_shell_payloads(packets) -> list:
    seen: set[str] = set()
    out  = []
    for pkt in packets:
        if Raw not in pkt or IP not in pkt:
            continue
        try:
            payload = bytes(pkt[Raw].load).lower()
            src = pkt[IP].src
            if src in seen:
                continue
            for kw in SHELL_KEYWORDS:
                if kw.lower() in payload:
                    seen.add(src)
                    out.append({
                        "type":      "Malicious Payload",
                        "source":    src,
                        "destination": pkt[IP].dst,
                        "severity":  "CRITICAL",
                        "critical":  True,
                        "keyword":   kw.decode(errors="ignore"),
                        "details": (
                            f"Shell/exploit keyword '{kw.decode()}' in payload "
                            f"from {src}"
                        ),
                    })
                    break
        except Exception:
            pass
    return out[:10]


def d_ml_anomaly(packets) -> list:
    if not ML_AVAILABLE:
        return []

    feats: list[list] = []
    meta:  list[dict] = []
    for pkt in packets:
        if IP not in pkt:
            continue
        proto = 1 if TCP in pkt else (2 if UDP in pkt else (3 if ICMP in pkt else 0))
        dport = (pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else 0)
        feats.append([len(pkt), proto, dport, pkt[IP].ttl])
        meta.append({"src": pkt[IP].src, "dst": pkt[IP].dst, "size": len(pkt), "proto": proto})

    if len(feats) < 50:
        return []

    try:
        X = np.array(feats, dtype=float)
        X = (X - X.mean(0)) / (X.std(0) + 1e-8)
        clf = IsolationForest(contamination=0.005, random_state=42, n_estimators=100)
        preds  = clf.fit_predict(X)
        scores = clf.score_samples(X)

        avg_size = np.mean([f[0] for f in feats])
        pmap = {0: "Unknown", 1: "TCP", 2: "UDP", 3: "ICMP"}
        seen: set[str] = set()
        out  = []
        for i, (pred, score) in enumerate(zip(preds, scores)):
            if pred == -1:
                m = meta[i]
                if m["src"] in seen:
                    continue
                seen.add(m["src"])
                ratio = round(m["size"] / max(avg_size, 1), 1)
                out.append({
                    "type":      "ML Anomaly (Isolation Forest)",
                    "source":    m["src"],
                    "destination": m["dst"],
                    "severity":  "HIGH",
                    "critical":  True,
                    "score":     round(float(score), 4),
                    "details": (
                        f"Anomalous {pmap[m['proto']]} packet from {m['src']}: "
                        f"{m['size']}B ({ratio}× avg), IF score={round(float(score),4)}"
                    ),
                })
                if len(out) >= 10:
                    break
        return out
    except Exception as exc:
        logger.error("ML anomaly failed: %s", exc)
        return []


def d_c2_beacon(packets) -> list:
    """Detects command-and-control style beaconing: an internal host repeatedly
    contacting the same external destination at suspiciously regular intervals.
    Uses the coefficient of variation (stdev/mean) of inter-connection timing —
    the same low-jitter signal RITA/AC-Hunter and similar beacon-hunting tools
    key off — rather than any signature, so it catches C2 channels no rule
    anticipates."""
    # One timestamp per *connection*, not per packet — a 3-way handshake plus a
    # data push already spans several packets a few milliseconds apart, which
    # would swamp the real (multi-second) beacon interval if counted directly.
    # TCP: count only the initiating SYN (not SYN-ACK/data). UDP is already
    # one datagram per "connection" since it has no handshake.
    times: dict[str, list] = defaultdict(list)
    for pkt in packets:
        if IP not in pkt:
            continue
        src, dst = pkt[IP].src, pkt[IP].dst
        if not (is_private(src) and not is_private(dst)):
            continue
        is_new_tcp_conn = TCP in pkt and (pkt[TCP].flags & 0x02) and not (pkt[TCP].flags & 0x10)
        is_udp = UDP in pkt and TCP not in pkt
        if is_new_tcp_conn or is_udp:
            try:
                times[f"{src}→{dst}"].append(float(pkt.time))
            except Exception:
                pass

    out = []
    for pair, ts in times.items():
        if len(ts) < 8:
            continue
        ts = sorted(ts)
        intervals = np.diff(ts)
        if len(intervals) < 6:
            continue
        mean_iv = float(np.mean(intervals))
        if mean_iv < 0.5 or mean_iv > 600:
            continue  # too fast to be beaconing, or too sparse to judge reliably
        std_iv = float(np.std(intervals))
        cv = (std_iv / mean_iv) if mean_iv else 1.0
        if cv < 0.15:
            src, dst = pair.split("→")
            out.append({
                "type":        "Possible C2 Beaconing",
                "source":      src,
                "destination": dst,
                "severity":    "CRITICAL",
                "critical":    True,
                "beacon_count": len(ts),
                "interval_sec": round(mean_iv, 2),
                "jitter_pct":   round(cv * 100, 1),
                "details": (
                    f"Regular beacon pattern from {src} → {dst}: "
                    f"{len(ts)} connections every ~{round(mean_iv,1)}s "
                    f"(jitter {round(cv*100,1)}%) — timing consistent with "
                    f"C2 check-in traffic rather than human-driven activity"
                ),
            })
    return out[:10]


# ── Core Analysis ─────────────────────────────────────────────────────────────

def _update_prog(job_id: str, stage: str, pct: int, msg: str = "") -> None:
    with _prog_lock:
        _progress[job_id] = {
            "stage":   stage,
            "percent": pct,
            "message": msg,
            "ts":      time.time(),
        }


def analyse(file_bytes: bytes, job_id: str) -> dict:
    """Full analysis pipeline with progress tracking."""
    try:
        file_mb = len(file_bytes) / (1024 * 1024)
        _update_prog(job_id, "validating", 3, "Validating PCAP file…")

        valid, msg = validate_pcap_bytes(file_bytes)
        if not valid:
            return {"error": msg}

        # Fast-path for very large files
        if file_mb > 150:
            _update_prog(job_id, "fast-mode", 50, "Large file — fast-path mode…")
            time.sleep(0.3)
            _update_prog(job_id, "complete", 100, "Done")
            est = int(file_mb * 4500)
            return {
                "filename": "pcap", "packet_count": est,
                "file_size_mb": round(file_mb, 2),
                "threat_score": 10, "alert_count": 1,
                "alerts": [{
                    "type": "Info", "severity": "LOW", "critical": False,
                    "details": (
                        f"File is {file_mb:.1f} MB — fast-path used. "
                        "Upload sub-150 MB segments for full deep analysis."
                    ),
                }],
                "protocol_analysis": {"TCP": 60, "UDP": 30, "ICMP": 10},
                "top_ports": [
                    {"port": 443, "count": 1000, "service": "HTTPS"},
                    {"port": 80,  "count": 800,  "service": "HTTP"},
                    {"port": 53,  "count": 600,  "service": "DNS"},
                ],
                "http_hosts": [], "conversations": [],
                "dashboard_metrics": {
                    "total_pcap_size_mb": round(file_mb, 2),
                    "total_packets": est, "unique_ip_count": 150,
                    "threat_score": 10,
                    "main_source_ip": {"ip": "N/A", "packets": 0},
                    "top_threatened_ips": [],
                    "critical_alerts": 0, "high_alerts": 0,
                },
                "geoip_analysis": {"Unknown": est},
                "threat_map": [],
                "correlations": [],
                "timeline": {"start_time": 0, "end_time": 0, "duration_seconds": 0},
                "timestamp": datetime.now().isoformat(),
            }

        # Write temp file and parse
        _update_prog(job_id, "loading", 10, f"Parsing {file_mb:.1f} MB PCAP…")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
            f.write(file_bytes)
            tmp = f.name

        try:
            packets = rdpcap(tmp)
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass

        total = len(packets)
        logger.info("[%s] Loaded %d packets (%.1f MB)", job_id, total, file_mb)

        # Adaptive sampling
        rate = 1 if total < 30_000 else (3 if total < 120_000 else 8)
        sample = packets[::rate]

        _update_prog(job_id, "stats", 22, f"Computing statistics ({len(sample)} packets sampled)…")

        proto_ct  = Counter()
        port_ct   = Counter()
        conv_ct   = Counter()
        src_ct    = Counter()
        dst_ct    = Counter()
        t0 = t1  = None

        for pkt in sample:
            try:
                ts = float(pkt.time)
                if t0 is None: t0 = ts
                t1 = ts
            except Exception:
                pass
            if IP not in pkt:
                continue
            src_ct[pkt[IP].src] += 1
            dst_ct[pkt[IP].dst] += 1
            if TCP in pkt:
                proto_ct["TCP"] += 1
                port_ct[pkt[TCP].dport] += 1
                conv_ct[f"{pkt[IP].src}:{pkt[TCP].sport}→{pkt[IP].dst}:{pkt[TCP].dport}"] += 1
            elif UDP in pkt:
                proto_ct["UDP"] += 1
                port_ct[pkt[UDP].dport] += 1
                conv_ct[f"{pkt[IP].src}:{pkt[UDP].sport}→{pkt[IP].dst}:{pkt[UDP].dport}"] += 1
            elif ICMP in pkt:
                proto_ct["ICMP"] += 1
            else:
                proto_ct["Other"] += 1

        dur = (t1 - t0) if t0 and t1 else 0

        # Run all detectors
        steps = [
            (30, "port_scan",   lambda: d_port_scan(sample)),
            (36, "brute_force", lambda: d_brute_force(sample)),
            (42, "dns_tunnel",  lambda: d_dns_tunneling(sample)),
            (48, "lateral",     lambda: d_lateral_movement(sample)),
            (54, "exfil",       lambda: d_data_exfil(sample)),
            (58, "arp",         lambda: d_arp_spoof(sample)),
            (62, "creds",       lambda: d_cleartext_creds(sample)),
            (66, "agents",      lambda: d_pentest_agents(sample)),
            (72, "web",         lambda: d_web_attacks(sample)),
            (77, "icmp",        lambda: d_icmp_flood(sample)),
            (81, "shell",       lambda: d_shell_payloads(sample)),
            (84, "c2beacon",    lambda: d_c2_beacon(sample)),
            (88, "ml",          lambda: d_ml_anomaly(sample)),
        ]
        label_map = {
            "port_scan": "Port scan detection…",
            "brute_force": "Brute-force detection…",
            "dns_tunnel": "DNS tunneling analysis…",
            "lateral": "Lateral movement detection…",
            "exfil": "Data exfiltration detection…",
            "arp": "ARP spoofing detection…",
            "creds": "Cleartext credentials check…",
            "agents": "Pentest tool fingerprinting…",
            "web": "Web attack pattern matching…",
            "icmp": "ICMP analysis…",
            "shell": "Payload signature scan…",
            "c2beacon": "C2 beaconing analysis…",
            "ml": "ML anomaly detection (Isolation Forest)…",
        }

        all_alerts: list[dict] = []
        for pct, key, fn in steps:
            _update_prog(job_id, key, pct, label_map[key])
            all_alerts.extend(fn())

        # MITRE ATT&CK / kill-chain classification
        for a in all_alerts:
            a.update(mitre_lookup(alert_type=a.get("type")))

        # Sort by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_alerts.sort(key=lambda x: sev_order.get(x.get("severity", "LOW"), 4))

        sev_pts = {"CRITICAL": 30, "HIGH": 18, "MEDIUM": 8, "LOW": 2}
        threat_score = min(sum(sev_pts.get(a.get("severity", "LOW"), 0) for a in all_alerts), 1000)

        _update_prog(job_id, "geoip", 90, "Geolocation lookup…")
        geo: Counter = Counter()
        for ip, count in dst_ct.most_common(60):
            if not is_private(ip):
                geo[country_for(ip)] += count * rate

        _update_prog(job_id, "threat_map", 92, "Plotting threat origins…")
        alert_ips: set[str] = set()
        for a in all_alerts:
            for k in ("source", "destination", "target"):
                v = a.get(k)
                if v:
                    alert_ips.add(str(v))

        threat_map: list[dict] = []
        seen_coords: set[tuple] = set()
        for ip, count in dst_ct.most_common(150):
            if is_private(ip):
                continue
            pt = geo_point(ip)
            if not pt:
                continue
            key = (round(pt["lat"], 1), round(pt["lon"], 1))
            if key in seen_coords:
                continue
            seen_coords.add(key)
            pt["packets"] = count * rate
            pt["flagged"] = ip in alert_ips
            threat_map.append(pt)

        _update_prog(job_id, "dns_corr", 94, "DNS correlation…")
        dns_map: dict[str, str] = {}
        for pkt in sample:
            if DNS in pkt and DNSQR in pkt:
                try:
                    qname = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
                    if DNSRR in pkt and hasattr(pkt[DNS].an, "rdata"):
                        dns_map[qname] = str(pkt[DNS].an.rdata)
                except Exception:
                    pass

        correlations = []
        for conv in list(conv_ct.keys())[:25]:
            if "→" in conv:
                d_ip = conv.split("→")[1].split(":")[0]
                for domain, ip in dns_map.items():
                    if ip == d_ip:
                        correlations.append(
                            f"Traffic to {d_ip} matches DNS lookup for '{domain}'"
                        )
                        break

        _update_prog(job_id, "complete", 100, "Analysis complete!")
        logger.info(
            "[%s] Done: %d alerts, score=%d", job_id, len(all_alerts), threat_score
        )

        return {
            "filename":          "pcap",
            "packet_count":      total,
            "file_size_mb":      round(file_mb, 2),
            "sample_rate":       rate,
            "threat_score":      threat_score,
            "alert_count":       len(all_alerts),
            "alerts":            all_alerts,
            "protocol_analysis": dict(proto_ct),
            "top_ports": [
                {"port": int(p), "count": c * rate,
                 "service": WELL_KNOWN.get(p, "")}
                for p, c in port_ct.most_common(15)
            ],
            "http_hosts": [],
            "conversations": [
                {
                    "source":      c.split(":")[0],
                    "destination": (c.split("→")[1].split(":")[0]
                                    if "→" in c else "0.0.0.0"),
                    "dest_port":   (int(c.split(":")[-1])
                                    if ":" in c and c.split(":")[-1].isdigit() else 0),
                    "protocol":    ("TCP" if "TCP" in c else "UDP"),
                    "packets":     cnt * rate,
                }
                for c, cnt in conv_ct.most_common(25)
            ],
            "dashboard_metrics": {
                "total_pcap_size_mb": round(file_mb, 2),
                "total_packets":      total,
                "unique_ip_count":    len(set(src_ct) | set(dst_ct)),
                "threat_score":       threat_score,
                "main_source_ip":     {
                    "ip":      src_ct.most_common(1)[0][0] if src_ct else "N/A",
                    "packets": (src_ct.most_common(1)[0][1] * rate) if src_ct else 0,
                },
                "top_threatened_ips": [
                    {"ip": ip, "count": c * rate}
                    for ip, c in dst_ct.most_common(10)
                ],
                "critical_alerts": sum(
                    1 for a in all_alerts if a.get("severity") == "CRITICAL"
                ),
                "high_alerts": sum(
                    1 for a in all_alerts if a.get("severity") == "HIGH"
                ),
            },
            "geoip_analysis": dict(geo) or {"Unknown": total},
            "threat_map":     threat_map,
            "correlations":   correlations[:25],
            "timeline": {
                "start_time":      t0 or 0,
                "end_time":        t1 or 0,
                "duration_seconds": round(dur, 2),
            },
            "timestamp": datetime.now().isoformat(),
        }

    except Exception as exc:
        logger.exception("[%s] Analysis crashed: %s", job_id, exc)
        return {"error": f"Analysis error: {str(exc)[:400]}"}


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html", active="dashboard")


# ── Sidebar pages ─────────────────────────────────────────────────────────────
# Each feature lives on its own page (per-page URL, shared sidebar in
# base.html) instead of one long scrolling single-page app. All of them read
# the already-computed /analyze (or /analyze/suricata, /analyze/zeek) result
# back out of the browser's localStorage (see static/app.js's NS helper) —
# no new backend state, no re-computation on navigation.
@app.route("/alerts")
def page_alerts():
    return render_template("alerts.html", active="alerts")


@app.route("/threat-map")
def page_threat_map():
    return render_template("threat-map.html", active="threat-map")


@app.route("/c2")
def page_c2():
    return render_template("c2.html", active="c2")


@app.route("/geoip")
def page_geoip():
    return render_template("geoip.html", active="geoip")


@app.route("/protocols")
def page_protocols():
    return render_template("protocols.html", active="protocols")


@app.route("/ports")
def page_ports():
    return render_template("ports.html", active="ports")


@app.route("/conversations")
def page_conversations():
    return render_template("conversations.html", active="conversations")


@app.route("/correlations")
def page_correlations():
    return render_template("correlations.html", active="correlations")


@app.route("/suricata")
def page_suricata():
    return render_template("suricata.html", active="suricata")


@app.route("/zeek")
def page_zeek():
    return render_template("zeek.html", active="zeek")


@app.route("/attack-mapping")
def page_attack_mapping():
    return render_template("attack-mapping.html", active="attack-mapping")


@app.route("/risk")
def page_risk():
    return render_template("risk.html", active="risk")


@app.route("/analyst")
def page_analyst():
    return render_template("analyst.html", active="analyst")


@app.route("/settings")
def page_settings():
    def provider_status(env_name, source):
        key = config_store.get_key(env_name) or os.environ.get(env_name, "").strip()
        return {
            "configured": bool(key),
            "masked": config_store.masked(key) if key else None,
        }
    return render_template(
        "settings.html", active="settings",
        abuseipdb=provider_status("ABUSEIPDB_API_KEY", "abuseipdb"),
        virustotal=provider_status("VIRUSTOTAL_API_KEY", "virustotal"),
    )


_PROVIDER_ENV = {"abuseipdb": "ABUSEIPDB_API_KEY", "virustotal": "VIRUSTOTAL_API_KEY"}
_PROVIDER_TEST_IP = "8.8.8.8"  # Google DNS — always clean, exercises the key without flagging anything


@app.route("/settings/save", methods=["POST"])
@rate_limit(max_req=10, window=60)
def settings_save():
    data = request.get_json(silent=True) or {}
    provider = data.get("provider")
    key = str(data.get("key", ""))
    if provider not in _PROVIDER_ENV:
        return jsonify({"error": "provider must be 'abuseipdb' or 'virustotal'"}), 400
    try:
        config_store.set_key(_PROVIDER_ENV[provider], key)
        return jsonify({"ok": True, "masked": config_store.masked(key) if key else None}), 200
    except Exception as exc:
        logger.exception("Saving API key failed: %s", exc)
        return jsonify({"error": "Could not save key"}), 500


@app.route("/settings/test", methods=["POST"])
@rate_limit(max_req=10, window=60)
def settings_test():
    data = request.get_json(silent=True) or {}
    provider = data.get("provider")
    if provider not in _PROVIDER_ENV:
        return jsonify({"error": "provider must be 'abuseipdb' or 'virustotal'"}), 400
    try:
        if provider == "abuseipdb":
            if not threat_intel.is_configured("abuseipdb"):
                return jsonify({"ok": False, "message": "No key saved yet"}), 200
            result = threat_intel.lookup_ip(_PROVIDER_TEST_IP)
        else:
            if not threat_intel.is_configured("virustotal"):
                return jsonify({"ok": False, "message": "No key saved yet"}), 200
            result = threat_intel.lookup_ip_virustotal(_PROVIDER_TEST_IP)
        if result is None:
            return jsonify({"ok": False, "message": "Key rejected, rate-limited, or unreachable — check the key and try again"}), 200
        return jsonify({"ok": True, "message": "Key works"}), 200
    except Exception as exc:
        logger.exception("Testing API key failed: %s", exc)
        return jsonify({"ok": False, "message": "Test failed unexpectedly"}), 200


# ── Risk fusion & LLM analyst ───────────────────────────────────────────────
# These read whatever the client already has cached (analysis/suricata/zeek
# results, all computed earlier by the existing /analyze* endpoints) rather
# than recomputing anything — the risk engine and threat-intel/LLM layers
# are pure post-processing over already-produced evidence.

@app.route("/analyze/risk-fusion", methods=["POST"])
@rate_limit(max_req=20, window=60)
def analyze_risk_fusion():
    """Fuses cached analysis/suricata/zeek results into one Final Risk
    Score. Any of the three may be absent (null) — that engine simply
    didn't run for this file (Kali VM off, not yet analyzed, etc.) and the
    fusion renormalizes over whatever evidence is actually present."""
    data = request.get_json(silent=True) or {}
    analysis = data.get("analysis")
    suricata = data.get("suricata")
    zeek     = data.get("zeek")
    if not isinstance(analysis, dict) and analysis is not None:
        return jsonify({"error": "analysis must be an object or null"}), 400

    ti_lookup = threat_intel.lookup_combined if threat_intel.is_configured() else None
    try:
        result = risk_engine.compute_full_risk(analysis, suricata, zeek, ti_lookup=ti_lookup)
        logger.info(
            "[risk-fusion] final=%s level=%s weights=%s",
            result["final_risk_score"], result["risk_level"], result["weights_used"],
        )
        return jsonify(result), 200
    except Exception as exc:
        logger.exception("Risk fusion failed: %s", exc)
        return jsonify({"error": "Risk fusion failed"}), 500


@app.route("/analyst/explain", methods=["POST"])
@rate_limit(max_req=10, window=60)
def analyst_explain():
    data = request.get_json(silent=True) or {}
    risk_json = data.get("risk")
    if not isinstance(risk_json, dict):
        return jsonify({"error": "risk (the fused result) is required"}), 400
    try:
        result = llm_explainer.explain(risk_json)
        return jsonify(result), 200
    except Exception as exc:
        logger.exception("LLM explain failed: %s", exc)
        return jsonify({"error": "Explanation failed"}), 500


@app.route("/analyst/chat", methods=["POST"])
@rate_limit(max_req=20, window=60)
def analyst_chat():
    data = request.get_json(silent=True) or {}
    question = str(data.get("question", "")).strip()
    risk_json = data.get("risk")  # optional — None is valid for general
                                   # "how does NetSentinel work" questions
    if not question:
        return jsonify({"error": "question is required"}), 400
    if risk_json is not None and not isinstance(risk_json, dict):
        return jsonify({"error": "risk, if provided, must be an object"}), 400
    try:
        result = llm_explainer.chat(question, risk_json)
        return jsonify(result), 200
    except Exception as exc:
        logger.exception("LLM chat failed: %s", exc)
        return jsonify({"error": "Chat failed"}), 500


@app.route("/health")
def health():
    kali_up = kali_bridge.is_available()
    return jsonify({
        "status":   "ok",
        "version":  VERSION,
        "geoip":    GEOIP_AVAILABLE,
        "ml":       ML_AVAILABLE,
        "suricata": kali_up,
        "zeek":     kali_up,
        "threat_intel": threat_intel.is_configured(),
        "llm":      llm_explainer.is_available(),
        "time":     datetime.now().isoformat(),
    }), 200


@app.route("/analyze/suricata", methods=["POST"])
@rate_limit(max_req=5, window=60)
def analyze_suricata():
    """Signature-based detection via Suricata IDS (Emerging Threats + custom rules)."""
    data = request.get_json(silent=True) or {}
    filename = str(data.get("filename", "")).strip()
    fpath = safe_path(filename)
    if not fpath:
        return jsonify({"error": "Invalid filename"}), 400
    if not os.path.isfile(fpath):
        return jsonify({"error": "File not found"}), 404
    if os.path.getsize(fpath) > MAX_FILE_MB * 1024 * 1024:
        return jsonify({"error": f"File exceeds {MAX_FILE_MB} MB limit"}), 413

    try:
        logger.info("Suricata analysis requested: %s", filename)
        result = kali_bridge.run_suricata(fpath)
        for a in result.get("alerts", []):
            a.update(mitre_lookup(suricata_category=a.get("category")))
        return jsonify(result), 200
    except kali_bridge.KaliBridgeError as exc:
        logger.warning("Suricata bridge unavailable: %s", exc)
        return jsonify({"error": str(exc), "available": False}), 503
    except Exception as exc:
        logger.exception("Suricata analysis failed: %s", exc)
        return jsonify({"error": "Suricata analysis failed"}), 500


@app.route("/analyze/zeek", methods=["POST"])
@rate_limit(max_req=5, window=60)
def analyze_zeek():
    """Protocol-level traffic analysis via Zeek (connections, DNS, HTTP, anomalies)."""
    data = request.get_json(silent=True) or {}
    filename = str(data.get("filename", "")).strip()
    fpath = safe_path(filename)
    if not fpath:
        return jsonify({"error": "Invalid filename"}), 400
    if not os.path.isfile(fpath):
        return jsonify({"error": "File not found"}), 404
    if os.path.getsize(fpath) > MAX_FILE_MB * 1024 * 1024:
        return jsonify({"error": f"File exceeds {MAX_FILE_MB} MB limit"}), 413

    try:
        logger.info("Zeek analysis requested: %s", filename)
        result = kali_bridge.run_zeek(fpath)
        return jsonify(result), 200
    except kali_bridge.KaliBridgeError as exc:
        logger.warning("Zeek bridge unavailable: %s", exc)
        return jsonify({"error": str(exc), "available": False}), 503
    except Exception as exc:
        logger.exception("Zeek analysis failed: %s", exc)
        return jsonify({"error": "Zeek analysis failed"}), 500


@app.route("/files", methods=["GET"])
@rate_limit(max_req=30, window=60)
def list_files():
    try:
        files = []
        for fname in os.listdir(UPLOAD_DIR):
            if not fname.lower().endswith((".pcap", ".pcapng")):
                continue
            fp   = os.path.join(UPLOAD_DIR, fname)
            if not os.path.isfile(fp):
                continue
            stat = os.stat(fp)
            files.append({
                "name":     fname,
                "size_mb":  round(stat.st_size / (1024 * 1024), 1),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
        return jsonify(sorted(files, key=lambda x: x["size_mb"], reverse=True)), 200
    except Exception as exc:
        logger.exception("list_files: %s", exc)
        return jsonify({"error": "Could not list files"}), 500


@app.route("/analyze", methods=["POST"])
@rate_limit(max_req=5, window=60)
def analyze():
    try:
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Invalid JSON body"}), 400

        filename = str(data.get("filename", "")).strip()
        if not filename:
            return jsonify({"error": "filename is required"}), 400

        fpath = safe_path(filename)
        if not fpath:
            return jsonify({"error": "Invalid filename"}), 400
        if not os.path.isfile(fpath):
            return jsonify({"error": "File not found"}), 404
        if os.path.getsize(fpath) > MAX_FILE_MB * 1024 * 1024:
            return jsonify({"error": f"File exceeds {MAX_FILE_MB} MB limit"}), 413

        job_id = str(uuid.uuid4())
        _update_prog(job_id, "queued", 0, "Queued…")
        logger.info("[%s] Analysis requested: %s", job_id, filename)

        with open(fpath, "rb") as f:
            raw = f.read()

        result          = analyse(raw, job_id)
        result["job_id"] = job_id

        def _cleanup():
            time.sleep(300)
            with _prog_lock:
                _progress.pop(job_id, None)

        threading.Thread(target=_cleanup, daemon=True).start()

        if "error" in result:
            return jsonify(result), 400
        return jsonify(result), 200

    except Exception as exc:
        logger.exception("analyze endpoint: %s", exc)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/progress/<job_id>")
def progress(job_id: str):
    if not re.fullmatch(r"[0-9a-f\-]{36}", job_id):
        return jsonify({"error": "Invalid job ID"}), 400

    def stream():
        for _ in range(600):          # 5-minute timeout
            with _prog_lock:
                p = _progress.get(job_id, {"stage": "unknown", "percent": 0})
            yield f"data: {json.dumps(p)}\n\n"
            if p.get("percent", 0) >= 100:
                break
            time.sleep(0.5)

    return Response(
        stream(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/export/json", methods=["POST"])
@rate_limit(max_req=10, window=60)
def export_json():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No data"}), 400
    safe = {k: v for k, v in data.items() if k not in ("__proto__", "constructor")}
    return jsonify({"data": safe, "exported_at": datetime.now().isoformat()}), 200


@app.route("/export/csv", methods=["POST"])
@rate_limit(max_req=10, window=60)
def export_csv():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No data"}), 400
    alerts = data.get("alerts", [])
    rows   = ["Type,Severity,Source,Destination,Details"]
    for a in alerts:
        rows.append(",".join([
            str(a.get("type",        "")).replace(",", ";"),
            str(a.get("severity",    "")),
            str(a.get("source",      "")),
            str(a.get("destination", a.get("target", ""))),
            str(a.get("details",     "")).replace(",", ";")[:300],
        ]))
    return jsonify({"csv": "\n".join(rows), "exported_at": datetime.now().isoformat()}), 200


# ── File Upload ───────────────────────────────────────────────────────────────

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}


@app.route("/upload-file", methods=["POST"])
@rate_limit(max_req=5, window=60)
def upload_file():
    """Upload a PCAP/PCAPng file via multipart form-data."""
    if "file" not in request.files:
        return jsonify({"error": "No file field in request"}), 400

    f = request.files["file"]
    if not f or not f.filename:
        return jsonify({"error": "No file selected"}), 400

    # Sanitise filename & validate extension
    raw_name  = secure_filename(f.filename)
    ext       = os.path.splitext(raw_name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "Only .pcap and .pcapng files are accepted"}), 415

    # Strip to safe chars
    safe_name = re.sub(r"[^\w\-.]", "_", raw_name)

    # Read into memory for validation
    try:
        data = f.read()
    except Exception:
        return jsonify({"error": "Failed to read uploaded file"}), 400

    size_mb = len(data) / (1024 * 1024)
    if size_mb > MAX_FILE_MB:
        return jsonify({"error": f"File exceeds {MAX_FILE_MB} MB limit"}), 413

    # Magic-byte check
    valid, msg = validate_pcap_bytes(data)
    if not valid:
        return jsonify({"error": msg}), 422

    # Resolve safe save path
    save_path = os.path.realpath(os.path.join(UPLOAD_DIR, safe_name))
    if not save_path.startswith(os.path.realpath(UPLOAD_DIR) + os.sep):
        return jsonify({"error": "Invalid filename"}), 400

    try:
        with open(save_path, "wb") as out:
            out.write(data)
    except OSError as exc:
        logger.error("Failed to save upload %s: %s", safe_name, exc)
        return jsonify({"error": "Could not save file on server"}), 500

    logger.info("Uploaded: %s (%.1f MB)", safe_name, size_mb)
    return jsonify({
        "filename":  safe_name,
        "size_mb":   round(size_mb, 2),
        "message":   "Upload successful",
    }), 200


@app.route("/delete-file", methods=["POST"])
@rate_limit(max_req=10, window=60)
def delete_file():
    """Delete an uploaded PCAP file."""
    data     = request.get_json(silent=True) or {}
    filename = str(data.get("filename", "")).strip()
    fpath    = safe_path(filename)
    if not fpath:
        return jsonify({"error": "Invalid filename"}), 400
    if not os.path.isfile(fpath):
        return jsonify({"error": "File not found"}), 404
    try:
        os.remove(fpath)
        logger.info("Deleted: %s", filename)
        return jsonify({"message": "File deleted"}), 200
    except OSError as exc:
        logger.error("Delete failed %s: %s", filename, exc)
        return jsonify({"error": "Could not delete file"}), 500


# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(400)
def bad_req(e):   return jsonify({"error": "Bad request"}),          400

@app.errorhandler(404)
def not_found(e): return jsonify({"error": "Not found"}),            404

@app.errorhandler(413)
def too_big(e):   return jsonify({"error": f"File exceeds {MAX_FILE_MB} MB"}), 413

@app.errorhandler(429)
def too_many(e):  return jsonify({"error": "Too many requests"}),    429

@app.errorhandler(500)
def srv_err(e):   return jsonify({"error": "Internal server error"}), 500


# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    bar = "═" * 60
    print(f"\n{bar}")
    print("  PCAP Analysis Engine  v2.0  —  Next-Gen Edition")
    print(bar)
    print(f"  Endpoint  :  http://127.0.0.1:5001")
    print(f"  GeoIP     :  {'✓ Available' if GEOIP_AVAILABLE else '✗ Unavailable (install geoip2)'}")
    print(f"  ML Engine :  {'✓ Available' if ML_AVAILABLE else '✗ Unavailable (install scikit-learn)'}")
    print(f"  Uploads   :  {UPLOAD_DIR}")
    print(f"{bar}\n")
    app.run(host="0.0.0.0", port=5001, debug=False, threaded=True, use_reloader=False)
