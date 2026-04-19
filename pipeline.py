"""
pipeline.py
-----------
Core processing pipeline for the Network Log Translator.

Public API:
    process_logs(raw_logs)  — batch: returns {summary, logs, time_to_clarity}
    process_log(raw_log)    — single: returns flat dict with time_to_clarity

Flow (batch):
    Raw log strings
        → Step 1: Validate + parse each log          (parser/log_parser.py)
        → Step 2: detect_anomalies(all parsed)        (detection/anomaly_detector.py)
        → Step 3: classify_log() per entry            (classifier/classifier.py)
        → Step 4: correlate_incidents(all enriched)   (inline — see below)
        → Step 5: generate_batch_explanation(all)     (summarizer/llm_summarizer.py)
        → Step 6: Build response — summary at top, logs as list
"""

import logging
import time
from collections import defaultdict
from typing import Any

from parser.log_parser          import parse_log
from detection.anomaly_detector import detect_anomalies
from classifier.classifier      import classify_log
from summarizer.llm_summarizer  import generate_batch_explanation, generate_explanation

logger = logging.getLogger(__name__)


# ── Incident correlation ──────────────────────────────────────────────────────

def _correlate_incidents(logs: list[dict]) -> list[dict]:
    """
    Group anomalous logs by source IP and mark them as part of an incident
    when the same IP shows multiple anomalies or anomalies across log types.

    Adds two fields to each log dict (does NOT remove or rename any existing field):
        incident        – bool
        incident_reason – str  (empty string when incident=False)

    Rules:
        - Same IP has 2+ separate anomaly entries  → incident
        - Same IP has anomalies from 2+ log types  → incident

    Args:
        logs: Enriched log dicts (must have is_anomaly, source_ip, log_type).

    Returns:
        Same list with incident fields attached in-place.
    """
    # Build per-IP anomaly profile: count of anomaly entries + set of log types
    # Only anomalous logs are counted — normal traffic from an IP is irrelevant.
    ip_anomaly_count: dict[str, int]       = defaultdict(int)
    ip_anomaly_types: dict[str, set[str]]  = defaultdict(set)

    for log in logs:
        if not log.get("is_anomaly"):
            continue
        ip = log.get("source_ip", "unknown")
        ip_anomaly_count[ip] += 1
        ip_anomaly_types[ip].add(log.get("log_type", "unknown"))

    # Decide which IPs qualify as incidents
    incident_ips: set[str] = set()
    for ip in ip_anomaly_count:
        if ip_anomaly_count[ip] >= 2 or len(ip_anomaly_types[ip]) >= 2:
            incident_ips.add(ip)

    # Tag every log — anomalous or not
    for log in logs:
        ip = log.get("source_ip", "unknown")
        if log.get("is_anomaly") and ip in incident_ips:
            log["incident"]        = True
            log["incident_reason"] = (
                "Multiple related anomalies from same source IP"
            )
        else:
            log["incident"]        = False
            log["incident_reason"] = ""

    return logs


# ── Batch pipeline (primary) ──────────────────────────────────────────────────

def process_logs(raw_logs: list[str]) -> dict[str, Any]:
    """
    End-to-end batch pipeline: list of raw log strings → structured batch result.

    Returns a dict with:
        summary          – plain-English LLM explanation for the whole batch
        time_to_clarity  – total processing time as a human-readable string
        logs             – list of per-log result dicts

    Each log dict contains:
        severity         – "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
        is_anomaly       – bool
        reason           – short technical explanation of any anomaly
        source_ip        – originating IP address (or "unknown")
        timestamp        – log timestamp string (or None)
        log_type         – "syslog" | "vpc_flow" | "snmp"
        incident         – bool  (True if IP is part of a correlated incident)
        incident_reason  – str   (human-readable reason, or "" if not incident)
    """
    start = time.time()

    # ── Step 1: Validate and parse ────────────────────────────────────────────
    parsed_logs: list[dict] = []
    for i, raw_log in enumerate(raw_logs):
        if not raw_log or not isinstance(raw_log, str) or not raw_log.strip():
            logger.warning("Skipping log[%d]: empty or invalid input.", i)
            continue
        parsed = parse_log(raw_log)
        if not parsed:
            logger.warning(
                "Skipping log[%d]: unrecognised format — %.80s", i, raw_log.strip()
            )
            continue
        parsed_logs.append(parsed)

    if not parsed_logs:
        logger.warning("No parseable logs in batch; returning empty result.")
        return {
            "summary":         "No recognisable log entries found in the submitted batch.",
            "time_to_clarity": f"{round(time.time() - start, 3)} sec",
            "logs":            [],
        }

    logger.debug("Parsed %d/%d log(s) successfully.", len(parsed_logs), len(raw_logs))

    # ── Step 2: Anomaly detection (full-batch, time-window aware) ─────────────
    enriched_logs = detect_anomalies(parsed_logs)
    logger.debug(
        "Detection complete — %d anomalie(s) in %d log(s).",
        sum(1 for l in enriched_logs if l.get("is_anomaly")),
        len(enriched_logs),
    )

    # ── Step 3: Severity classification ──────────────────────────────────────
    for enriched in enriched_logs:
        enriched["severity"] = classify_log(enriched)

    # ── Step 4: Incident correlation ─────────────────────────────────────────
    enriched_logs = _correlate_incidents(enriched_logs)
    incident_count = sum(1 for l in enriched_logs if l.get("incident"))
    if incident_count:
        logger.info(
            "Incident correlation: %d log(s) grouped into correlated incidents.",
            incident_count,
        )

    # ── Step 5: ONE LLM call for the entire batch ─────────────────────────────
    summary = generate_batch_explanation(enriched_logs)
    logger.debug("Batch LLM call complete — summary length: %d chars.", len(summary))

    # ── Step 6: Build output ──────────────────────────────────────────────────
    log_results: list[dict[str, Any]] = []
    for enriched in enriched_logs:
        log_results.append({
            "severity":        enriched["severity"],
            "is_anomaly":      enriched.get("is_anomaly", False),
            "reason":          enriched.get("reason", ""),
            "source_ip":       enriched.get("source_ip", "unknown"),
            "timestamp":       enriched.get("timestamp"),
            "log_type":        enriched.get("log_type", "unknown"),
            "incident":        enriched.get("incident", False),
            "incident_reason": enriched.get("incident_reason", ""),
        })

    return {
        "summary":         summary,
        "time_to_clarity": f"{round(time.time() - start, 3)} sec",
        "logs":            log_results,
    }


# ── Single-log convenience wrapper ────────────────────────────────────────────

def process_log(raw_log: str) -> dict[str, Any]:
    """
    Process a single raw log line.

    Returns:
        On success — flat result dict:
            severity, is_anomaly, reason, explanation,
            source_ip, timestamp, log_type,
            incident, incident_reason, time_to_clarity
        On failure — {"error": "<message>"}
    """
    start = time.time()

    if not raw_log or not isinstance(raw_log, str) or not raw_log.strip():
        return {"error": "Invalid log: input must be a non-empty string."}

    parsed = parse_log(raw_log)
    if not parsed:
        return {
            "error": (
                "Invalid log: unrecognised format. "
                "Supported: syslog, VPC flow, SNMP trap."
            )
        }

    enriched = detect_anomalies([parsed])[0]
    enriched["severity"] = classify_log(enriched)

    # Single-log incident correlation: a lone log can never form an incident
    enriched["incident"]        = False
    enriched["incident_reason"] = ""

    explanation = generate_explanation(enriched)

    return {
        "severity":        enriched["severity"],
        "is_anomaly":      enriched.get("is_anomaly", False),
        "reason":          enriched.get("reason", ""),
        "explanation":     explanation,
        "source_ip":       enriched.get("source_ip", "unknown"),
        "timestamp":       enriched.get("timestamp"),
        "log_type":        enriched.get("log_type", "unknown"),
        "incident":        enriched["incident"],
        "incident_reason": enriched["incident_reason"],
        "time_to_clarity": f"{round(time.time() - start, 3)} sec",
    }
