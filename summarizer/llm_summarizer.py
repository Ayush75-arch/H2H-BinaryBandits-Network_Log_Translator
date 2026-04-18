"""
summarizer/llm_summarizer.py
-----------------------------
LLM-powered batch summary generator using Ollama (LLaMA 3).

Optimised for real-time use:
  - ONE Ollama call per batch (not per log)
  - Short, token-capped prompt  (num_predict: 80)
  - Low temperature             (0.2) for fast, deterministic output
  - 60-second timeout with graceful fallback
  - CRITICAL/HIGH threats are surfaced first in the prompt
"""

import json
import logging

import requests

logger = logging.getLogger(__name__)

# ── Ollama configuration ──────────────────────────────────────────────────────

OLLAMA_URL      = "http://localhost:11434/api/generate"
OLLAMA_MODEL    = "llama3:8b"
REQUEST_TIMEOUT = 60

_OLLAMA_OPTIONS = {
    "temperature": 0.2,
    "top_p":       0.9,
    "num_predict": 80,   # slightly wider budget to cover critical threat mention
}

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
        "Network security event. "
        "Reply in 1-2 sentences only. No bullet points, no markdown, no lists. "
        "State what happened and clearly say whether immediate action is needed.\n\n"
        f"[{severity}] {source_ip}: {reason}"
    )


# ── Shared Ollama caller ──────────────────────────────────────────────────────

def _call_ollama(prompt: str) -> str:
    """
    POST a prompt to Ollama and return the response text.
    All error paths return _FALLBACK — callers never need to handle exceptions.
    """
    payload = {
        "model":   OLLAMA_MODEL,
        "prompt":  prompt,
        "stream":  False,
        "options": _OLLAMA_OPTIONS,
    }
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        text = response.json().get("response", "").strip()
        if not text:
            logger.warning("Ollama returned an empty response; using fallback.")
            return _FALLBACK
        return text
    except requests.exceptions.ConnectionError:
        logger.warning("Ollama not reachable at %s; using fallback.", OLLAMA_URL)
        return _FALLBACK
    except requests.exceptions.Timeout:
        logger.warning("Ollama timed out after %ss; using fallback.", REQUEST_TIMEOUT)
        return _FALLBACK
    except requests.exceptions.HTTPError as exc:
        logger.error("Ollama HTTP error: %s; using fallback.", exc)
        return _FALLBACK
    except (json.JSONDecodeError, KeyError) as exc:
        logger.error("Failed to parse Ollama response: %s; using fallback.", exc)
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
    logger.debug("Sending batch prompt to Ollama (%d log(s)).", len(logs))
    return _call_ollama(prompt)


def generate_explanation(log: dict) -> str:
    """
    Generate a plain-English explanation for a single log entry.
    Kept for backward compatibility with the single-log /analyze endpoint.
    """
    prompt = _build_single_prompt(log)
    logger.debug("Sending single-log prompt to Ollama.")
    return _call_ollama(prompt)
