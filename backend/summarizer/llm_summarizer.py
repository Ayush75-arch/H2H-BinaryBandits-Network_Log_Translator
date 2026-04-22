"""
summarizer/llm_summarizer.py
-----------------------------
LLM-powered batch summary generator using Groq API (LLaMA 3).

Optimised for real-time use:
  - ONE Groq call per batch (not per log)
  - Short, token-capped prompt  (max_tokens: 80)
  - Low temperature             (0.2) for fast, deterministic output
  - Graceful fallback on any API error
  - CRITICAL/HIGH threats are surfaced first in the prompt
"""

import logging
import os

from groq import Groq

logger = logging.getLogger(__name__)

# ── Groq configuration ────────────────────────────────────────────────────────

_GROQ_MODEL  = "llama-3.1-8b-instant"
_groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))

_FALLBACK = (
    "Suspicious or anomalous activity detected. "
    "Review the severity and reason fields for details."
)

# Severity sort order — lower = more important (surfaced first in prompt)
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ── Prompt builders ───────────────────────────────────────────────────────────

def _build_batch_prompt(logs: list[dict]) -> str:
    """
    Build a compact prompt for the batch, with CRITICAL and HIGH entries first.

    Strategy:
      1. Sort logs by severity (CRITICAL → HIGH → MEDIUM → LOW → INFO).
      2. Deduplicate by (severity, reason) so 50 identical lines = 1 entry.
      3. Cap at 8 representative lines to keep the prompt under ~450 chars.
      4. If any CRITICAL entry exists, prepend an explicit instruction to
         mention the critical threat — the LLM respects this reliably.
    """
    # Sort anomalous logs first, then by severity rank
    sorted_logs = sorted(
        logs,
        key=lambda l: (
            0 if l.get("is_anomaly") else 1,
            _SEVERITY_ORDER.get(l.get("severity", "INFO"), 4),
        ),
    )

    seen: set[tuple] = set()
    lines: list[str] = []
    has_critical = False

    for log in sorted_logs:
        severity   = log.get("severity", "INFO")
        source_ip  = log.get("source_ip", "unknown")
        is_anomaly = log.get("is_anomaly", False)
        reason     = log.get("reason", "Normal activity")

        key = (severity, reason)
        if key in seen:
            continue
        seen.add(key)

        if severity == "CRITICAL":
            has_critical = True

        status = f"ANOMALY — {reason}" if is_anomaly else "normal"
        lines.append(f"{len(lines) + 1}. [{severity}] {source_ip}: {status}")

        if len(lines) >= 8:
            break

    log_summary = "\n".join(lines)

    # Prepend a critical-threat instruction when warranted
    critical_instruction = (
        "There is a CRITICAL threat — explicitly mention it. "
        if has_critical
        else ""
    )

    return (
        f"Network security event summary. {critical_instruction}"
        "Reply in 1-2 sentences only. No bullet points, no markdown, no lists. "
        "Lead with the most severe issue and state whether immediate action is needed.\n\n"
        f"{log_summary}"
    )


def _build_single_prompt(log: dict) -> str:
    """Compact single-log prompt for the /analyze endpoint."""
    severity  = log.get("severity", "INFO")
    source_ip = log.get("source_ip", "unknown")
    reason    = (
        log.get("reason", "Normal activity")
        if log.get("is_anomaly")
        else "normal traffic"
    )
    return (
        "Network security event requiring SOC analyst assessment. "
        "Reply in exactly 2-3 sentences using this structure: "
        "1) What pattern was observed (include IP and specifics). "
        "2) Why this is a threat (attack technique and risk). "
        "3) What action is required right now. "
        "No bullet points, no markdown, no generic statements.\n\n"
        f"[{severity}] {source_ip}: {reason}"
    )


# ── Shared Groq caller ───────────────────────────────────────────────────────

def _call_groq(prompt: str) -> str:
    """
    Send a prompt to Groq and return the response text.
    All error paths return _FALLBACK — callers never need to handle exceptions.
    """
    try:
        response = _groq_client.chat.completions.create(
            model=_GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior SOC analyst writing structured threat assessments. "
                        "Every response must follow this exact 3-part structure: "
                        "[What happened — specific pattern with IP/counts]. "
                        "[Why it is a threat — attack technique and risk]. "
                        "[Impact and required action — what the analyst must do now]. "
                        "Be specific, technical, and actionable. No generic statements. "
                        "Include source IP, thresholds, and confidence where available."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=180,
        )
        text = response.choices[0].message.content.strip()
        if not text:
            logger.warning("Groq returned an empty response; using fallback.")
            return _FALLBACK
        return text
    except Exception as exc:
        logger.error("Groq API error: %s; using fallback.", exc)
        return _FALLBACK


# ── Public API ────────────────────────────────────────────────────────────────

def generate_batch_explanation(logs: list[dict]) -> str:
    """
    Generate ONE plain-English summary for an entire batch of logs.
    CRITICAL/HIGH threats are surfaced first in the prompt so the LLM
    leads with the most important issue.
    """
    if not logs:
        return _FALLBACK
    prompt = _build_batch_prompt(logs)
    logger.debug("Sending batch prompt to Groq (%d log(s)).", len(logs))
    return _call_groq(prompt)


def generate_explanation(log: dict) -> str:
    """
    Generate a plain-English explanation for a single log entry.
    Kept for backward compatibility with the single-log /analyze endpoint.
    """
    prompt = _build_single_prompt(log)
    logger.debug("Sending single-log prompt to Groq.")
    return _call_groq(prompt)
