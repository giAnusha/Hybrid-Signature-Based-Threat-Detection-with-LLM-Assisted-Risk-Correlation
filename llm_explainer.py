"""
Local LLM analyst layer, via Ollama's local HTTP API — explanation and chat
ONLY. This module never computes a score, a MITRE mapping, or an IP
reputation; it only narrates numbers risk_engine.py already produced.

Model: Llama 3.2:3b (Q4_K_M quantization, Ollama's default) — 3B-class is
the realistic ceiling given this project's own environment has repeatedly
shown under 4GB of free RAM with the Kali VM running; a 1B model would need
less RAM but loses too much on structured multi-field explanation quality,
and an 8B+ model risks the same memory-pressure hangs seen earlier this
session with the Kali VM. The model name is a module-level constant, not
hardcoded through the call sites, so it's a one-line change if a different
model suits the hardware better later.

Every request also sets a short `keep_alive` — the model unloads from RAM
shortly after the last request rather than sitting loaded indefinitely,
since this machine's RAM budget is tight and the LLM step is meant to run
standalone, not fight the Kali VM/Suricata/Zeek for memory.

Design contract (matches the project's own rules):
  * The LLM receives ONLY the structured JSON risk_engine.py already
    computed — no packet data, no raw logs, no tool/function-calling access
    that could let it "recompute" a number.
  * The system prompt explicitly forbids inventing scores, IP reputations,
    or MITRE technique IDs not present in the supplied JSON.
  * If Ollama isn't running/installed (the current state of this machine —
    verified, not installed, this session), both explain() and chat() fall
    back to a canned template built directly from the JSON, so the
    dashboard's Risk/Analyst pages never show a broken or blank state.
"""
import json
import logging
import os

import requests

logger = logging.getLogger("pcap-engine.llm_explainer")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KNOWLEDGE_FILE = os.path.join(BASE_DIR, "llm_knowledge.md")

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL_NAME = os.environ.get("NETSENTINEL_LLM_MODEL", "llama3.2:3b")
REQUEST_TIMEOUT = 150  # measured ~60-70s for a full explanation on this machine's
                        # CPU-only inference (no GPU) — generous headroom above that
KEEP_ALIVE = "3m"  # unload the model from RAM 3 minutes after the last request


def _load_app_knowledge() -> str:
    """Loads llm_knowledge.md — a plain-language description of how the
    whole NetSentinel platform actually works (architecture, all three
    detection engines, the exact risk-fusion formula, MITRE mapping
    methodology). Included in every request's system prompt, not just the
    per-analysis JSON, so the assistant can answer questions about the
    *system* ("how does your risk score work?", "what does Suricata do
    here?") and not only the one result it's explaining.

    This is a deliberate alternative to fine-tuning: editing this file takes
    effect on the next request with zero retraining, zero GPU requirement,
    and no risk of degrading the base model's general reasoning — the right
    tradeoff for a 3B model on this hardware. Falls back to an empty string
    (never raises) if the file is ever moved/deleted, so a missing knowledge
    doc degrades to "less context" rather than breaking the assistant."""
    try:
        with open(KNOWLEDGE_FILE, encoding="utf-8") as f:
            return f.read()
    except OSError as exc:
        logger.warning("Could not load llm_knowledge.md (non-fatal): %s", exc)
        return ""


APP_KNOWLEDGE = _load_app_knowledge()

SYSTEM_PROMPT = (
    "You are a SOC analyst assistant embedded in a network-forensics dashboard. "
    "You will be given a JSON object containing the ALREADY-COMPUTED results of "
    "a deterministic detection pipeline (Suricata, Zeek, a behavioural/ML engine, "
    "and threat intelligence), fused into a final risk score. "
    "Your only job is to explain these results in clear, concise language for a "
    "security analyst. "
    "STRICT RULES: "
    "1) Never invent a score, alert, IP reputation, or MITRE technique that is "
    "not present in the JSON you were given. "
    "2) If something is not present in the JSON (e.g. a score is null/None), say "
    "explicitly that this evidence is unavailable — do not guess or fill it in. "
    "3) Do not recalculate or second-guess the final_risk_score — treat it as "
    "ground truth and explain WHY it came out that way using the evidence fields. "
    "4) Keep answers grounded, specific, and reference the actual numbers/fields "
    "given to you. "
    "5) For MITRE ATT&CK techniques, the JSON gives you the exact technique ID "
    "AND its correct name (e.g. {\"id\": \"T1190\", \"name\": \"Exploit "
    "Public-Facing Application\"}) — use that name exactly as given. Do NOT "
    "describe what you believe a technique ID means from your own training "
    "data; your knowledge of MITRE ATT&CK IDs may be incomplete or wrong, and "
    "the name in the JSON is always the correct one. "
    "6) You may also be asked general questions about how NetSentinel itself "
    "works (its architecture, detectors, scoring formulas) — answer those "
    "using the system knowledge below, not the per-request JSON."
)

# Sent with every request: the strict behavioural rules above, plus the full
# app-knowledge document (loaded once at import — see _load_app_knowledge).
if APP_KNOWLEDGE:
    FULL_SYSTEM_PROMPT = (
        SYSTEM_PROMPT
        + "\n\n=== NETSENTINEL SYSTEM KNOWLEDGE (how the platform actually works) ===\n\n"
        + APP_KNOWLEDGE
    )
else:
    FULL_SYSTEM_PROMPT = SYSTEM_PROMPT


def is_available() -> bool:
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=2)
        return r.status_code == 200
    except requests.RequestException:
        return False


def _fallback_explanation(analysis_json: dict) -> str:
    """Deterministic, template-based explanation used whenever Ollama isn't
    reachable — not as good as an LLM's prose, but never blank and never
    wrong, since it's built directly from the same JSON."""
    d = analysis_json
    lines = [
        f"[Local LLM unavailable — showing a template summary of the computed results instead]",
        "",
        f"Final Risk Score: {d.get('final_risk_score', 'N/A')}/100 ({d.get('risk_level', 'Unknown')})",
        "",
        "Per-engine scores:",
        f"  Suricata: {d.get('suricata_score', 'not run')}",
        f"  Zeek: {d.get('zeek_score', 'not run')}",
        f"  Behavioural/ML: {d.get('ml_score', 'not run')}",
        f"  Threat Intelligence: {d.get('threat_intel_score', 'not configured')}",
        "",
    ]
    ev = d.get("evidence", {})
    labels = {"ml": "Behavioural/ML", "threat_intel": "Threat Intelligence"}
    for engine, items in ev.items():
        if items:
            label = labels.get(engine, engine.capitalize())
            lines.append(f"{label} evidence: " + "; ".join(items))
    if d.get("c2_indicators"):
        lines.append("")
        lines.append("C2 indicators observed: " + ", ".join(d["c2_indicators"]))
    if d.get("mitre_techniques"):
        techs = ", ".join(f"{t['id']} ({t['name']})" for t in d["mitre_techniques"])
        lines.append("MITRE ATT&CK techniques: " + techs)
    return "\n".join(lines)


def _call_ollama(prompt: str) -> str | None:
    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": MODEL_NAME, "prompt": prompt, "system": FULL_SYSTEM_PROMPT,
                  "stream": False, "keep_alive": KEEP_ALIVE},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            logger.warning("Ollama returned HTTP %s", resp.status_code)
            return None
        return resp.json().get("response", "").strip() or None
    except requests.RequestException as exc:
        logger.warning("Ollama call failed (non-fatal): %s", exc)
        return None


def explain(analysis_json: dict) -> dict:
    """Returns {"text": "...", "source": "llm"|"fallback"}."""
    prompt = (
        "Explain this network-traffic risk analysis to a security analyst. "
        "Cover: what was detected, why it's suspicious, what each engine "
        "(Suricata, Zeek, ML/behavioural, threat intel) contributed, why the "
        "final score is what it is, the relevant MITRE ATT&CK technique(s), "
        "and what to investigate next.\n\n"
        f"JSON:\n{json.dumps(analysis_json, indent=2)}"
    )
    text = _call_ollama(prompt)
    if text:
        return {"text": text, "source": "llm", "model": MODEL_NAME}
    return {"text": _fallback_explanation(analysis_json), "source": "fallback", "model": None}


def chat(question: str, context_json: dict | None) -> dict:
    """RAG-by-context-stuffing: the full current analysis JSON is included
    with every question, every time, rather than relying on the model to
    remember or a vector store to retrieve the right facts — appropriate at
    this scale (one capture's worth of structured results, not a corpus),
    and it's the surest way to keep the model from drifting away from the
    actual evidence over a multi-turn conversation.

    context_json may be None — that's a valid, expected case for a general
    question about how NetSentinel itself works ("how is the risk score
    calculated?") asked before any file has been analyzed. The system
    prompt's app-knowledge document (FULL_SYSTEM_PROMPT) answers those; only
    per-file specifics genuinely require context_json."""
    if context_json:
        prompt = (
            f"An analyst asks: \"{question}\"\n\n"
            "Answer using the JSON below for anything about THIS specific "
            "analysis. If the question is about how NetSentinel works in "
            "general, use the system knowledge instead. If neither covers "
            "the answer, say the evidence is unavailable rather than guessing.\n\n"
            f"JSON:\n{json.dumps(context_json, indent=2)}"
        )
    else:
        prompt = (
            f"An analyst asks: \"{question}\"\n\n"
            "No specific file analysis is currently loaded — answer using "
            "only the NetSentinel system knowledge in your instructions. If "
            "the question requires a specific analysis result you don't "
            "have, say so and suggest running an analysis first."
        )
    text = _call_ollama(prompt)
    if text:
        return {"text": text, "source": "llm", "model": MODEL_NAME}
    fallback_tail = _fallback_explanation(context_json) if context_json else (
        "No specific analysis is loaded, and I can't reach general "
        "knowledge without the local LLM running."
    )
    return {
        "text": ("Local LLM (Ollama) is not running, so I can't answer free-form questions right now. "
                  + ("Here's the underlying data instead:\n\n" if context_json else "")
                  + fallback_tail),
        "source": "fallback", "model": None,
    }
