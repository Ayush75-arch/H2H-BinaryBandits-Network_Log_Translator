import re
import json

# ─────────────────────────────────────────────
# Protocol map for AWS VPC Flow Logs
# ─────────────────────────────────────────────
PROTOCOL_MAP = {
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP",
    "47": "GRE",
    "50": "ESP",
    "58": "ICMPv6",
    "132": "SCTP",
}


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _empty_record(log_type: str = "") -> dict:
    """Return a zeroed-out standard record."""
    return {
        "timestamp": None,
        "source_ip": "unknown",
        "destination_ip": None,
        "port": None,
        "protocol": None,
        "event": None,
        "log_type": log_type,
    }


# ─────────────────────────────────────────────
# 1. Syslog parser  (original, preserved)
# ─────────────────────────────────────────────

def parse_syslog(log: str) -> dict | None:
    """
    Parse a syslog-formatted string and extract timestamp, source IP, and event.
    Returns a standardised record dict, or None if the line cannot be parsed.
    """
    if not log or not isinstance(log, str):
        return None

    log = log.strip()

    timestamp_pattern = r'^(?P<timestamp>\w{3}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2})'
    ts_match = re.match(timestamp_pattern, log)
    if not ts_match:
        return None

    timestamp = ts_match.group("timestamp")
    remainder = log[ts_match.end():].strip()

    remainder_pattern = r'^\s*\S+\s+\S+?:\s*(?P<message>.+)$'
    rem_match = re.match(remainder_pattern, remainder, re.DOTALL)
    message = rem_match.group("message").strip() if rem_match else remainder.strip()

    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_match = re.search(ip_pattern, message)
    source_ip = ip_match.group() if ip_match else "unknown"

    record = _empty_record("syslog")
    record.update({
        "timestamp": timestamp,
        "source_ip": source_ip,
        "event": message,
    })
    return record


# ─────────────────────────────────────────────
# 2. AWS VPC Flow Log parser
# ─────────────────────────────────────────────

# Field positions in the default VPC flow log format (version 2):
# version account-id interface-id srcaddr dstaddr srcport dstport
#         protocol packets bytes start end action log-status
_VPC_FIELDS = (
    "version", "account_id", "interface_id",
    "srcaddr", "dstaddr",
    "srcport", "dstport",
    "protocol", "packets", "bytes",
    "start", "end",
    "action", "log_status",
)


def parse_vpc_flow(log: str) -> dict | None:
    """
    Parse an AWS VPC Flow Log line (default v2 format, space-delimited).
    Returns a standardised record dict, or None if the line cannot be parsed.
    """
    if not log or not isinstance(log, str):
        return None

    parts = log.strip().split()

    # Minimum viable fields: version .. log_status = 14 tokens
    if len(parts) < len(_VPC_FIELDS):
        return None

    fields = dict(zip(_VPC_FIELDS, parts))

    proto_num = fields.get("protocol", "-")
    protocol = PROTOCOL_MAP.get(proto_num, proto_num)

    src = fields.get("srcaddr", "unknown")
    dst = fields.get("dstaddr", None)
    port = fields.get("dstport", None)
    action = fields.get("action", "UNKNOWN")

    event = (
        f"Traffic {action} from {src} to {dst} "
        f"on port {port} ({protocol})"
    )

    # VPC flow logs carry Unix epoch timestamps, not human-readable strings
    start_epoch = fields.get("start")
    timestamp = start_epoch if start_epoch and start_epoch != "-" else None

    record = _empty_record("vpc_flow")
    record.update({
        "timestamp": timestamp,
        "source_ip": src,
        "destination_ip": dst,
        "port": port,
        "protocol": protocol,
        "event": event,
    })
    return record


# ─────────────────────────────────────────────
# 3. SNMP Trap parser
# ─────────────────────────────────────────────

def parse_snmp_trap(log: str) -> dict | None:
    """
    Parse a simple SNMP trap log line.
    Expected pattern:  [optional timestamp] SNMP Trap: <trap_name> from <ip>
    Returns a standardised record dict, or None if the line cannot be parsed.
    """
    if not log or not isinstance(log, str):
        return None

    log = log.strip()

    # Optional leading timestamp  e.g.  "Jun  5 12:00:00 "
    timestamp = None
    ts_pattern = r'^(?P<ts>\w{3}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    ts_match = re.match(ts_pattern, log)
    if ts_match:
        timestamp = ts_match.group("ts")
        log = log[ts_match.end():]

    # Core SNMP trap pattern
    trap_pattern = r'SNMP\s+Trap\s*:\s*(?P<trap>\S+)\s+from\s+(?P<ip>\S+)'
    trap_match = re.search(trap_pattern, log, re.IGNORECASE)
    if not trap_match:
        return None

    source_ip = trap_match.group("ip")
    trap_name = trap_match.group("trap")
    event = log  # preserve full original message as event

    record = _empty_record("snmp_trap")
    record.update({
        "timestamp": timestamp,
        "source_ip": source_ip,
        "event": event,
    })
    return record


# ─────────────────────────────────────────────
# 4. Unified auto-detect parser
# ─────────────────────────────────────────────

_MONTH_ABBREVS = re.compile(
    r'^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b',
    re.IGNORECASE
)


def parse_log(log: str) -> dict | None:
    """
    Auto-detect log type and delegate to the appropriate parser.

    Detection rules:
      • Syslog  — line starts with a 3-letter month abbreviation
      • VPC     — line starts with a digit (version number)
      • SNMP    — line contains the literal string "SNMP Trap"

    Returns a standardised dict or None on failure.
    """
    if not log or not isinstance(log, str):
        return None

    stripped = log.strip()

    if re.search(r'SNMP\s+Trap', stripped, re.IGNORECASE):
        return parse_snmp_trap(stripped)

    if _MONTH_ABBREVS.match(stripped):
        return parse_syslog(stripped)

    if stripped and stripped[0].isdigit():
        return parse_vpc_flow(stripped)

    return None


# ─────────────────────────────────────────────
# 5. Test / integration block
# ─────────────────────────────────────────────

def _read_log_file(path: str) -> list[str]:
    """Read lines from a log file; return empty list on missing file."""
    try:
        with open(path, "r") as f:
            return f.readlines()
    except FileNotFoundError:
        print(f"  ⚠  File not found: {path}  (skipping)")
        return []


def _print_result(index: int, raw: str, result: dict | None) -> None:
    print(f"\n[Log {index}] Raw:")
    print(f"  {raw.strip()}")
    if result is None:
        print("  ⚠  Result: Unable to parse")
    else:
        pretty = json.dumps(result, indent=4).replace("\n", "\n  ")
        print(f"  ✔  Parsed:\n  {pretty}")


if __name__ == "__main__":
    LOG_FILES = [
        "logs/syslog.log",
        "logs/vpc_flow.log",
        "logs/snmp.log",
    ]

    print("=" * 60)
    print("  Multi-Log Parser — Integration Test")
    print("=" * 60)

    total = 0
    for log_file in LOG_FILES:
        lines = _read_log_file(log_file)
        if not lines:
            continue

        print(f"\n{'─' * 60}")
        print(f"  Source: {log_file}  ({len(lines)} line(s))")
        print(f"{'─' * 60}")

        for i, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            total += 1
            result = parse_log(line)
            _print_result(total, line, result)

    print("\n" + "=" * 60)
    print(f"  Done — {total} log(s) processed.")
    print("=" * 60)
