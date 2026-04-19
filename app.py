"""
app.py
------
FastAPI application for the Network Log Translator.

Endpoints:
    POST /analyze       — single log  (backward-compatible)
    POST /analyze/batch — batch logs  (improved response format)
"""

import logging
from logging.handlers import RotatingFileHandler
from typing import Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

from pipeline import process_log, process_logs

# ── File + console logging ────────────────────────────────────────────────────
_fmt = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"

logging.basicConfig(level=logging.INFO, format=_fmt)

# RotatingFileHandler: 1 MB per file, keep 3 backups → max 4 MB on disk
_file_handler = RotatingFileHandler(
    "app.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8"
)
_file_handler.setLevel(logging.INFO)
_file_handler.setFormatter(logging.Formatter(_fmt))

# Attach to the root logger so all modules write to the same file
logging.getLogger().addHandler(_file_handler)

logger = logging.getLogger(__name__)
logger.info("Network Log Translator starting up — file logging active.")

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="Network Log Translator",
    description=(
        "Parses raw network logs (syslog, VPC flow, SNMP), "
        "detects anomalies, classifies severity, correlates incidents, "
        "and generates a plain-English explanation."
    ),
    version="5.0.0",
)


# ── Request schemas ───────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    """Input: a single raw log line."""
    log: str

    @field_validator("log")
    @classmethod
    def log_must_not_be_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("'log' field must be a non-empty string.")
        return value.strip()


class AnalyzeBatchRequest(BaseModel):
    """Input: a list of raw log lines."""
    logs: list[str]

    @field_validator("logs")
    @classmethod
    def logs_must_not_be_empty(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("'logs' list must contain at least one entry.")
        return value


# ── Response schemas ──────────────────────────────────────────────────────────

class AnalyzeResponse(BaseModel):
    """Single-log analysis result."""
    severity:        str
    is_anomaly:      bool
    reason:          str
    explanation:     str
    source_ip:       str
    timestamp:       Optional[str]
    log_type:        Optional[str]
    incident:        bool
    incident_reason: str
    time_to_clarity: str


class LogEntry(BaseModel):
    """Per-log entry inside a batch response."""
    severity:        str
    is_anomaly:      bool
    reason:          str
    source_ip:       str
    timestamp:       Optional[str]
    log_type:        Optional[str]
    incident:        bool
    incident_reason: str


class BatchAnalyzeResponse(BaseModel):
    """
    Batch analysis result.
    One LLM summary at top; individual log entries below without repeated text.
    """
    summary:         str
    time_to_clarity: str
    logs:            list[LogEntry]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
def root():
    """Health check."""
    return {"status": "ok", "service": "Network Log Translator", "version": "5.0.0"}


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze a single raw network log line",
)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Parse, detect anomalies, classify, and explain a single raw log line.

    - **log**: A raw syslog, AWS VPC Flow Log, or SNMP trap line.
    """
    logger.info("Single log received: %.120s…", request.log)
    try:
        result = process_log(request.log)
    except Exception as exc:
        logger.error("Error processing single log: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected internal error occurred.",
        ) from exc

    if "error" in result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result["error"],
        )

    logger.info(
        "Single log done — severity=%s anomaly=%s incident=%s ttc=%s",
        result["severity"], result["is_anomaly"],
        result["incident"], result["time_to_clarity"],
    )
    return AnalyzeResponse(**result)


@app.post(
    "/analyze/batch",
    response_model=BatchAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze multiple raw network log lines",
)
def analyze_batch(request: AnalyzeBatchRequest) -> BatchAnalyzeResponse:
    """
    Parse, detect anomalies, classify, correlate, and explain a batch of logs.

    Returns:
    - **summary**: Single plain-English LLM explanation (CRITICAL threats first).
    - **time_to_clarity**: Total pipeline duration.
    - **logs**: Per-log results with severity, anomaly flag, incident flag, etc.
    """
    logger.info("Batch received: %d log(s).", len(request.logs))
    try:
        result = process_logs(request.logs)
    except Exception as exc:
        logger.error("Error processing batch: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected internal error occurred.",
        ) from exc

    if not result.get("logs"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "No logs could be parsed. "
                "Check that entries are valid syslog, VPC flow, or SNMP trap lines."
            ),
        )

    anomalies  = sum(1 for r in result["logs"] if r.get("is_anomaly"))
    incidents  = sum(1 for r in result["logs"] if r.get("incident"))
    logger.info(
        "Batch done — %d logs, %d anomalies, %d incident logs, ttc=%s",
        len(result["logs"]), anomalies, incidents, result["time_to_clarity"],
    )
    return BatchAnalyzeResponse(
        summary=result["summary"],
        time_to_clarity=result["time_to_clarity"],
        logs=[LogEntry(**entry) for entry in result["logs"]],
    )


# ── Error handler ─────────────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    """Return a clean JSON error instead of a raw stack trace."""
    logger.error("Unhandled exception: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected internal error occurred."},
    )


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
