import re
import json
from datetime import datetime, timezone

# ─────────────────────────────────────────────
# Protocol map for AWS VPC Flow Logs
# ─────────────────────────────────────────────
PROTOCOL_MAP = {
    "1":   "ICMP",
    "6":   "TCP",
    "17":  "UDP",
    "47":  "GRE",
    "50":  "ESP",
    "58":  "ICMPv6",
    "132": "SCTP",
}


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _empty_record(log_type: str = "") -> dict:
    """Return a zeroed-out standard record."""
    return {
        "timestamp":      None,
        "source_ip":      "unknown",
        "destination_ip": None,
        "port":           None,
        "protocol":       None,
        "event":          None,
        "log_type":       log_type,
    }


def _epoch_to_readable(epoch_str: str) -> str | None:
    """
    Convert a Unix epoch string to a human-readable UTC timestamp.
    Returns the original string unchanged if conversion fails.
    """
    try:
        ts = datetime.fromtimestamp(int(epoch_str), tz=timezone.utc)
        return ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError, OverflowError):
        return epoch_str  # graceful fallback — never crash


_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


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

    ip_match = _IP_RE.search(message)
    source_ip = ip_match.group() if ip_match else "unknown"

    record = _empty_record("syslog")
    record.update({
        "timestamp": timestamp,
        "source_ip": source_ip,
        "event":     message,
    })
    return record


# ─────────────────────────────────────────────
# 2. AWS VPC Flow Log parser
# ─────────────────────────────────────────────

_VPC_FIELDS_14 = (
    "version", "account_id", "interface_id",
    "srcaddr", "dstaddr",
    "srcport", "dstport",
    "protocol", "packets", "bytes",
    "start", "end",
    "action", "log_status",
)

_VPC_FIELDS_12 = (
    "version", "account_id", "interface_id",
    "srcaddr", "dstaddr",
    "srcport", "dstport",
    "protocol", "packets", "bytes",
    "action", "log_status",
)


def parse_vpc_flow(log: str) -> dict | None:
    """
    Parse an AWS VPC Flow Log line (default v2 format, space-delimited).
    Timestamps are converted from Unix epoch to a human-readable UTC string.
    Returns a standardised record dict, or None if the line cannot be parsed.
    """
    if not log or not isinstance(log, str):
        return None

    parts = log.strip().split()

    if len(parts) >= 14:
        fields = dict(zip(_VPC_FIELDS_14, parts))
    elif len(parts) >= 12:
        fields = dict(zip(_VPC_FIELDS_12, parts))
    else:
        return None

    proto_num = fields.get("protocol", "-")
    protocol  = PROTOCOL_MAP.get(proto_num, proto_num)

    src    = fields.get("srcaddr", "unknown")
    dst    = fields.get("dstaddr", None)
    port   = fields.get("dstport", None)
    action = fields.get("action", "UNKNOWN")

    event = (
        f"Traffic {action} from {src} to {dst} "
        f"on port {port} ({protocol})"
    )

    start_epoch = fields.get("start")
    timestamp = (
        _epoch_to_readable(start_epoch)
        if start_epoch and start_epoch != "-"
        else None
    )

    record = _empty_record("vpc_flow")
    record.update({
        "timestamp":      timestamp,
        "source_ip":      src,
        "destination_ip": dst,
        "port":           port,
        "protocol":       protocol,
        "event":          event,
    })
    return record


# ─────────────────────────────────────────────
# 3. SNMP Trap parser
# ─────────────────────────────────────────────

def parse_snmp_trap(log: str) -> dict | None:
    """
    Parse a simple SNMP trap log line.
    Expected pattern:  [optional timestamp] SNMP Trap: <trap_name> from <ip>

    Extracts trap_type (e.g. linkDown, authenticationFailure, coldStart)
    as a dedicated field for use by the anomaly detector and classifier.

    Returns a standardised record dict, or None if the line cannot be parsed.
    """
    if not log or not isinstance(log, str):
        return None

    log = log.strip()

    timestamp = None
    ts_pattern = r'^(?P<ts>\w{3}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    ts_match = re.match(ts_pattern, log)
    if ts_match:
        timestamp = ts_match.group("ts")
        log = log[ts_match.end():]

    trap_pattern = r'SNMP\s+Trap\s*:\s*(?P<trap>\S+)\s+from\s+(?P<ip>\S+)'
    trap_match = re.search(trap_pattern, log, re.IGNORECASE)
    if not trap_match:
        return None

    source_ip = trap_match.group("ip")
    trap_name = trap_match.group("trap")
    event     = log

    record = _empty_record("snmp")
    record.update({
        "timestamp": timestamp,
        "source_ip": source_ip,
        "trap_type": trap_name,
        "event":     event,
    })
    return record


# ─────────────────────────────────────────────
# 4. RFC 5424 Syslog parser  (NEW)
# ─────────────────────────────────────────────

# Pattern: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
# e.g. <34>1 2026-04-18T19:42:21Z firewall-1 sshd 1024 - - Failed password ...
_RFC5424_RE = re.compile(
    r'^<\d+>1\s+'
    r'(?P<timestamp>\S+)\s+'   # ISO timestamp
    r'\S+\s+'                  # hostname
    r'\S+\s+'                  # app-name
    r'\S+\s+'                  # procid
    r'\S+\s+'                  # msgid
    r'\S+\s+'                  # structured-data
    r'(?P<message>.+)$',
    re.DOTALL,
)


def parse_rfc5424(log: str) -> dict | None:
    """
    Parse an RFC 5424 structured syslog line.
    Returns a standardised record dict, or None if the line cannot be parsed.
    """
    if not log or not isinstance(log, str):
        return None

    m = _RFC5424_RE.match(log.strip())
    if not m:
        return None

    timestamp = m.group("timestamp")
    message   = m.group("message").strip()

    ip_match  = _IP_RE.search(message)
    source_ip = ip_match.group() if ip_match else "unknown"

    record = _empty_record("syslog")
    record.update({
        "timestamp": timestamp,
        "source_ip": source_ip,
        "event":     message,
    })
    return record


# ─────────────────────────────────────────────
# 5. Apache / Nginx access log parser  (NEW)
# ─────────────────────────────────────────────

# e.g.  192.168.1.10 - - [18/Apr/2026:19:42:21 +0000] "GET /admin HTTP/1.1" 401 512
_APACHE_RE = re.compile(
    r'^(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]'
    r'\s+"(?P<request>[^"]+)"'
    r'\s+(?P<status>\d{3})'
    r'\s+\S+',
)


def parse_apache(log: str) -> dict | None:
    """
    Parse a Combined Log Format (Apache / Nginx) access log line.
    Returns a standardised record dict, or None if the line cannot be parsed.
    """
    if not log or not isinstance(log, str):
        return None

    m = _APACHE_RE.match(log.strip())
    if not m:
        return None

    record = _empty_record("web")
    record.update({
        "timestamp": m.group("timestamp"),
        "source_ip": m.group("src_ip"),
        "event":     f'{m.group("request")} [HTTP {m.group("status")}]',
    })
    return record


# ─────────────────────────────────────────────
# 6. Firewall log parser  (NEW)
# ─────────────────────────────────────────────

# e.g.  DENY TCP from 192.168.1.100 to 10.0.0.5 port 22
_FIREWALL_RE = re.compile(
    r'^(?P<action>DENY|ALLOW)\s+'
    r'(?P<protocol>\S+)\s+'
    r'from\s+(?P<src>\S+)\s+'
    r'to\s+(?P<dst>\S+)'
    r'(?:\s+port\s+(?P<port>\d+))?',
    re.IGNORECASE,
)


def parse_firewall(log: str) -> dict | None:
    """
    Parse a simple DENY/ALLOW firewall log line.
    Returns a standardised record dict, or None if the line cannot be parsed.
    """
    if not log or not isinstance(log, str):
        return None

    m = _FIREWALL_RE.match(log.strip())
    if not m:
        return None

    record = _empty_record("firewall")
    record.update({
        "source_ip":      m.group("src"),
        "destination_ip": m.group("dst"),
        "port":           m.group("port"),
        "protocol":       m.group("protocol").upper(),
        "event":          log.strip(),
    })
    return record


# ─────────────────────────────────────────────
# 7. Windows Security Event log parser  (NEW)
# ─────────────────────────────────────────────

# e.g.  EventID=4625 AccountName=admin FailureReason=Bad password SourceIP=192.168.1.50
_WINDOWS_EVENTID_RE = re.compile(r'EventID=(?P<eid>\d+)')
_WINDOWS_SRCIP_RE   = re.compile(r'SourceIP=(?P<ip>\S+)')
_WINDOWS_KV_RE      = re.compile(r'(\w+)=([^\s=]+(?:\s+[^\s=]+)*?)(?=\s+\w+=|$)')


def parse_windows(log: str) -> dict | None:
    """
    Parse a simplified Windows Security Event log line (key=value pairs).
    Returns a standardised record dict, or None if the line cannot be parsed.
    """
    if not log or not isinstance(log, str):
        return None

    stripped = log.strip()

    if not _WINDOWS_EVENTID_RE.search(stripped):
        return None

    ip_match  = _WINDOWS_SRCIP_RE.search(stripped)
    source_ip = ip_match.group("ip") if ip_match else "unknown"

    record = _empty_record("windows")
    record.update({
        "source_ip": source_ip,
        "event":     stripped,
    })
    return record


# ─────────────────────────────────────────────
# 8. DNS query log parser  (NEW)
# ─────────────────────────────────────────────

# e.g.  DNS Query from 192.168.1.20 for suspicious-domain.xyz
_DNS_RE = re.compile(
    r'DNS\s+Query\s+from\s+(?P<src>\S+)\s+for\s+(?P<domain>\S+)',
    re.IGNORECASE,
)


def parse_dns(log: str) -> dict | None:
    """
    Parse a simple DNS query log line.
    Returns a standardised record dict, or None if the line cannot be parsed.
    """
    if not log or not isinstance(log, str):
        return None

    m = _DNS_RE.search(log.strip())
    if not m:
        return None

    record = _empty_record("dns")
    record.update({
        "source_ip": m.group("src"),
        "event":     log.strip(),
    })
    return record


# ─────────────────────────────────────────────
# 9. Unified auto-detect parser  (UPDATED)
# ─────────────────────────────────────────────

_MONTH_ABBREVS = re.compile(
    r'^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b',
    re.IGNORECASE
)

# Apache: starts with an IP address followed by " - "
_APACHE_LEAD = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}\s+-\s+')


def parse_log(log: str) -> dict | None:
    """
    Auto-detect log type and delegate to the appropriate parser.

    Detection order:
      1. SNMP       — contains "SNMP Trap"
      2. RFC 5424   — starts with "<N>1 "
      3. Apache/Nginx — IP then "- -" then [timestamp]
      4. Firewall   — starts with DENY or ALLOW
      5. Windows    — contains "EventID="
      6. DNS        — contains "DNS Query"
      7. Syslog     — starts with a 3-letter month abbreviation
      8. VPC Flow   — starts with a digit

    Returns a standardised dict or None on failure.
    """
    if not log or not isinstance(log, str):
        return None

    stripped = log.strip()

    # 1. SNMP
    if re.search(r'SNMP\s+Trap', stripped, re.IGNORECASE):
        return parse_snmp_trap(stripped)

    # 2. RFC 5424 syslog
    if stripped.startswith("<"):
        return parse_rfc5424(stripped)

    # 3. Apache / Nginx
    if _APACHE_LEAD.match(stripped):
        return parse_apache(stripped)

    # 4. Firewall
    if re.match(r'^(DENY|ALLOW)\s', stripped, re.IGNORECASE):
        return parse_firewall(stripped)

    # 5. Windows Security Event
    if "EventID=" in stripped:
        return parse_windows(stripped)

    # 6. DNS
    if re.search(r'DNS\s+Query', stripped, re.IGNORECASE):
        return parse_dns(stripped)

    # 7. Legacy syslog (month-prefix)
    if _MONTH_ABBREVS.match(stripped):
        return parse_syslog(stripped)

    # 8. VPC Flow Log
    if stripped and stripped[0].isdigit():
        return parse_vpc_flow(stripped)

    return None


# ─────────────────────────────────────────────
# 10. Test / integration block
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
        "logs/vpc.log",
        "logs/snmp.log",
    ]

    # Quick smoke-test of the five new parsers
    NEW_FORMAT_SAMPLES = [
        # RFC 5424
        "<34>1 2026-04-18T19:42:21Z firewall-1 sshd 1024 - - Failed password for invalid user admin from 192.168.1.45 port 51422 ssh2",
        # Apache
        '192.168.1.10 - - [18/Apr/2026:19:42:21 +0000] "GET /admin HTTP/1.1" 401 512',
        # Firewall
        "DENY TCP from 192.168.1.100 to 10.0.0.5 port 22",
        # Windows
        "EventID=4625 AccountName=admin FailureReason=Bad password SourceIP=192.168.1.50",
        # DNS
        "DNS Query from 192.168.1.20 for suspicious-domain.xyz",
    ]

    print("=" * 60)
    print("  New Format Smoke Test")
    print("=" * 60)
    for i, sample in enumerate(NEW_FORMAT_SAMPLES, 1):
        result = parse_log(sample)
        _print_result(i, sample, result)

    print("\n" + "=" * 60)
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
