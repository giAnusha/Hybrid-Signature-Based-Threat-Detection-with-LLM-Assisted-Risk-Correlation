"""
Kali VM bridge — runs Suricata (signature-based IDS) and Zeek (protocol analyzer)
against uploaded PCAPs inside the Kali VM, using VMware's guest-operations channel
(vmrun) instead of the network, so it works regardless of the VM's IP/SSH state.
"""

import json
import logging
import os
import subprocess
import tempfile
import uuid

logger = logging.getLogger("pcap-engine.kali_bridge")

VMRUN_PATH = os.environ.get(
    "VMRUN_PATH",
    r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
)
VMX_PATH = os.environ.get(
    "KALI_VMX_PATH",
    os.path.expanduser(r"~\Downloads\kali-linux-2025.2-vmware-amd64\kali-linux-2025.2-vmware-amd64.vmwarevm\kali-linux-2025.2-vmware-amd64.vmx"),
)
GUEST_USER = os.environ.get("KALI_GUEST_USER", "kali")
GUEST_PASS = os.environ.get("KALI_GUEST_PASS", "kali")

_VMRUN_BASE = [VMRUN_PATH, "-T", "ws", "-gu", GUEST_USER, "-gp", GUEST_PASS]

SEVERITY_MAP = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM"}


class KaliBridgeError(RuntimeError):
    """Raised when the Kali VM is unreachable or a guest command fails."""


def is_available() -> bool:
    try:
        result = subprocess.run(
            [VMRUN_PATH, "list"], capture_output=True, text=True, timeout=15
        )
        return VMX_PATH.lower() in result.stdout.lower()
    except Exception:
        return False


def _run_vmrun(args: list, timeout: int) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            _VMRUN_BASE + args, capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError:
        raise KaliBridgeError("vmrun.exe not found — is VMware Workstation installed?")
    except subprocess.TimeoutExpired:
        raise KaliBridgeError(f"Kali VM operation timed out after {timeout}s")
    if result.returncode != 0:
        raise KaliBridgeError(
            f"vmrun {' '.join(args[:1])} failed: {(result.stderr or result.stdout).strip()[:300]}"
        )
    return result


def _copy_to_guest(local_path: str, guest_path: str) -> None:
    try:
        size_mb = os.path.getsize(local_path) / (1024 * 1024)
    except OSError:
        size_mb = 0
    timeout = max(60, int(size_mb * 2))
    _run_vmrun(["copyFileFromHostToGuest", VMX_PATH, local_path, guest_path], timeout=timeout)


def _copy_from_guest(guest_path: str, local_path: str) -> None:
    _run_vmrun(["copyFileFromGuestToHost", VMX_PATH, guest_path, local_path], timeout=60)


def _run_script_in_guest(script_text: str, out_guest_path: str, timeout: int) -> str:
    """Writes script_text to the guest and runs it; the script must write its own
    output to out_guest_path (redirection via vmrun's argv doesn't go through a shell)."""
    job = uuid.uuid4().hex[:12]
    local_script = os.path.join(tempfile.gettempdir(), f"nst_{job}.sh")
    guest_script = f"/tmp/nst_{job}.sh"
    with open(local_script, "w", newline="\n", encoding="utf-8") as f:
        f.write(script_text)
    try:
        _copy_to_guest(local_script, guest_script)
        _run_vmrun(["runProgramInGuest", VMX_PATH, "/bin/bash", guest_script], timeout=timeout)
        local_out = os.path.join(tempfile.gettempdir(), f"nst_{job}.out")
        _copy_from_guest(out_guest_path, local_out)
        with open(local_out, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        os.unlink(local_out)
        return content
    finally:
        try:
            os.unlink(local_script)
        except OSError:
            pass
        _cleanup_guest_paths([guest_script])


def _cleanup_guest_paths(paths: list) -> None:
    if not paths:
        return
    script = "rm -rf " + " ".join(f'"{p}"' for p in paths) + "\n"
    job = uuid.uuid4().hex[:8]
    local_script = os.path.join(tempfile.gettempdir(), f"nst_cleanup_{job}.sh")
    guest_script = f"/tmp/nst_cleanup_{job}.sh"
    try:
        with open(local_script, "w", newline="\n", encoding="utf-8") as f:
            f.write(script)
        _copy_to_guest(local_script, guest_script)
        _run_vmrun(["runProgramInGuest", VMX_PATH, "/bin/bash", guest_script], timeout=30)
    except Exception as exc:
        logger.warning("Guest cleanup failed (non-fatal): %s", exc)
    finally:
        try:
            os.unlink(local_script)
        except OSError:
            pass


def parse_zeek_log(text: str) -> list:
    """Parses Zeek's tab-separated log format (#fields header + data rows)."""
    fields = None
    rows = []
    for line in text.splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        elif line.startswith("#") or not line.strip():
            continue
        elif fields:
            values = line.split("\t")
            if len(values) == len(fields):
                rows.append(dict(zip(fields, values)))
    return rows


def run_suricata(pcap_path: str, timeout: int = 180) -> dict:
    if not is_available():
        raise KaliBridgeError("Kali VM is not running")

    job = uuid.uuid4().hex[:12]
    guest_pcap = f"/tmp/nst_{job}.pcap"
    guest_outdir = f"/tmp/nst_{job}_suricata"
    guest_out = f"{guest_outdir}/bridge_run.out"

    script = f"""#!/bin/bash
mkdir -p {guest_outdir}
{{
echo {GUEST_PASS} | sudo -S suricata -r {guest_pcap} -l {guest_outdir} -k none --runmode single 2>&1
echo {GUEST_PASS} | sudo -S chmod -R a+r {guest_outdir}
}} > {guest_out} 2>&1
"""
    try:
        _copy_to_guest(pcap_path, guest_pcap)
        _run_script_in_guest(script, guest_out, timeout=timeout)

        local_eve = os.path.join(tempfile.gettempdir(), f"nst_{job}_eve.json")
        try:
            _copy_from_guest(f"{guest_outdir}/eve.json", local_eve)
        except KaliBridgeError:
            return {
                "engine": "suricata", "available": True,
                "alert_count": 0, "alerts": [], "signatures_loaded": 0,
                "note": "Suricata produced no eve.json (0 packets or engine error).",
            }

        alerts = []
        sig_count = 0
        try:
            with open(local_eve, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if evt.get("event_type") == "stats":
                        engines = evt.get("stats", {}).get("detect", {}).get("engines") or [{}]
                        sig_count = engines[0].get("rules_loaded", sig_count)
                    if evt.get("event_type") != "alert":
                        continue
                    a = evt.get("alert", {})
                    severity_num = a.get("severity")
                    alerts.append({
                        "type": "Suricata: " + a.get("signature", "Unknown Signature"),
                        "signature": a.get("signature", "Unknown"),
                        "sid": a.get("signature_id"),
                        "category": a.get("category", ""),
                        "severity": SEVERITY_MAP.get(severity_num, "MEDIUM"),
                        "critical": isinstance(severity_num, int) and severity_num <= 2,
                        "source": f"{evt.get('src_ip','?')}:{evt.get('src_port','')}",
                        "destination": f"{evt.get('dest_ip','?')}:{evt.get('dest_port','')}",
                        "protocol": evt.get("proto", ""),
                        "timestamp": evt.get("timestamp", ""),
                        "engine": "suricata",
                        "details": (
                            f"[Suricata sid:{a.get('signature_id')}] {a.get('signature','')} "
                            f"({a.get('category','')}) — {evt.get('src_ip','?')} → {evt.get('dest_ip','?')}"
                        ),
                    })
        finally:
            os.unlink(local_eve)

        return {
            "engine": "suricata",
            "available": True,
            "alert_count": len(alerts),
            "alerts": alerts,
            "signatures_loaded": sig_count,
        }
    finally:
        _cleanup_guest_paths([guest_pcap, guest_outdir])


def run_zeek(pcap_path: str, timeout: int = 180) -> dict:
    if not is_available():
        raise KaliBridgeError("Kali VM is not running")

    job = uuid.uuid4().hex[:12]
    guest_pcap = f"/tmp/nst_{job}.pcap"
    guest_outdir = f"/tmp/nst_{job}_zeek"
    guest_out = f"{guest_outdir}/bridge_run.out"

    script = f"""#!/bin/bash
mkdir -p {guest_outdir}
{{
cd {guest_outdir} && /opt/zeek/bin/zeek -C -r {guest_pcap} 2>&1
cd {guest_outdir} && tar czf logs.tar.gz *.log 2>/dev/null
}} > {guest_out} 2>&1
"""
    try:
        _copy_to_guest(pcap_path, guest_pcap)
        _run_script_in_guest(script, guest_out, timeout=timeout)

        local_tar = os.path.join(tempfile.gettempdir(), f"nst_{job}_zeek.tar.gz")
        try:
            _copy_from_guest(f"{guest_outdir}/logs.tar.gz", local_tar)
        except KaliBridgeError:
            return {
                "engine": "zeek", "available": True,
                "connections": [], "protocol_breakdown": {}, "weird_events": [],
                "notices": [], "dns_queries": [], "http_requests": [],
                "note": "Zeek produced no logs for this capture.",
            }

        import tarfile
        extract_dir = os.path.join(tempfile.gettempdir(), f"nst_{job}_zeek_logs")
        os.makedirs(extract_dir, exist_ok=True)
        with tarfile.open(local_tar, "r:gz") as tf:
            tf.extractall(extract_dir, filter="data")
        os.unlink(local_tar)

        def read_log(name):
            p = os.path.join(extract_dir, name)
            if not os.path.isfile(p):
                return []
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                return parse_zeek_log(f.read())

        conns = read_log("conn.log")
        weird = read_log("weird.log")
        notices = read_log("notice.log")
        dns_rows = read_log("dns.log")
        http_rows = read_log("http.log")

        proto_breakdown = {}
        for c in conns:
            p = c.get("proto", "other").upper()
            proto_breakdown[p] = proto_breakdown.get(p, 0) + 1

        top_conns = [
            {
                "source_ip": c.get("id.orig_h", "?"),
                "source_port": c.get("id.orig_p", ""),
                "destination_ip": c.get("id.resp_h", "?"),
                "destination_port": c.get("id.resp_p", ""),
                "protocol": c.get("proto", "").upper(),
                "service": c.get("service", "-"),
                "duration": c.get("duration", "-"),
                "orig_bytes": c.get("orig_bytes", "0"),
                "resp_bytes": c.get("resp_bytes", "0"),
                "conn_state": c.get("conn_state", ""),
            }
            for c in conns[:100]
        ]

        weird_events = [
            {
                "name": w.get("name", ""),
                "source": w.get("id.orig_h", ""),
                "destination": w.get("id.resp_h", ""),
                "details": f"Zeek anomaly '{w.get('name','')}': {w.get('id.orig_h','?')} → {w.get('id.resp_h','?')}",
            }
            for w in weird[:50]
        ]

        notice_events = [
            {
                "note": n.get("note", ""),
                "msg": n.get("msg", ""),
                "source": n.get("id.orig_h", ""),
                "destination": n.get("id.resp_h", ""),
            }
            for n in notices[:50]
        ]

        dns_queries = [
            {"query": d.get("query", ""), "source": d.get("id.orig_h", ""), "answer": d.get("answers", "")}
            for d in dns_rows[:50] if d.get("query") not in (None, "-", "")
        ]

        http_requests = [
            {
                "host": h.get("host", ""),
                "uri": h.get("uri", ""),
                "method": h.get("method", ""),
                "source": h.get("id.orig_h", ""),
                "status_code": h.get("status_code", ""),
            }
            for h in http_rows[:50]
        ]

        for f in os.listdir(extract_dir):
            try:
                os.unlink(os.path.join(extract_dir, f))
            except OSError:
                pass
        os.rmdir(extract_dir)

        return {
            "engine": "zeek",
            "available": True,
            "connection_count": len(conns),
            "connections": top_conns,
            "protocol_breakdown": proto_breakdown,
            "weird_events": weird_events,
            "weird_count": len(weird),
            "notices": notice_events,
            "dns_queries": dns_queries,
            "http_requests": http_requests,
        }
    finally:
        _cleanup_guest_paths([guest_pcap, guest_outdir])
