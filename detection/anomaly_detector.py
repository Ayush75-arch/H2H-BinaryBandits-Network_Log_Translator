"""
anomaly_detector.py
-------------------
Rule-based cybersecurity log anomaly detection engine.

Rules:
  1. Brute Force        — >=3 failed SSH logins from same IP (time-window aware)
  2. Traffic Spike      — source IP appears >5 times in VPC logs
  3. Repeated REJECTs   — multiple REJECT events in VPC logs
  4. SNMP Auth Fail     — event contains 'authenticationFailure'
  5. Link Flapping      — >=3 linkDown traps from same IP
  6. VPC Packet/Byte    — single VPC entry with packets>2000 or bytes>100000
  7. Firewall Port Scan — >=3 DENY events from same IP in firewall logs
  8. Web Brute Force    — >=2 HTTP 401 responses from same IP in web logs
"""

from collections import Counter, defaultdict
from datetime import datetime, timezone

# ── Thresholds (easy to tune) ─────────────────────────────────────────────────
_BRUTE_FORCE_THRESHOLD   = 3       # failed logins to flag as brute force
_BRUTE_FORCE_WINDOW_SEC  = 60      # sliding window in seconds (time-aware path)
_LINKDOWN_FLAP_THRESHOLD = 3       # linkDown traps to flag as flapping
_VPC_SPIKE_THRESHOLD     = 5       # VPC entries from same IP to flag as spike
_VPC_PACKET_THRESHOLD    = 2000    # packets in a single VPC entry → spike
_VPC_BYTE_THRESHOLD      = 100_000 # bytes  in a single VPC entry → spike
_FW_PORTSCAN_THRESHOLD   = 3       # DENY events from same IP → port scan
_WEB_BRUTEFORCE_THRESHOLD = 2      # HTTP 401s from same IP → web brute force


# ── Timestamp parsing (stdlib only, no external deps) ─────────────────────────

def _parse_timestamp(ts: str | None) -> datetime | None:
    """
    Parse a timestamp string into a timezone-aware datetime.

    Supports:
      - ISO 8601 / RFC 3339  e.g. "2024-01-15T08:01:00Z"
      - Syslog shortform      e.g. "Jun 10 14:23:01"   (year assumed = current)
      - Human-readable UTC    e.g. "2021-01-01 00:00:00 UTC"

    Returns None on any parse failure so callers can fall back gracefully.
    """
    if not ts or not isinstance(ts, str):
        return None

    ts = ts.strip()

    # ISO 8601 with trailing Z
    if ts.endswith("Z"):
        try:
            return datetime.fromisoformat(ts[:-1]).replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    # ISO 8601 with offset  e.g. "2024-01-15T08:01:00+00:00"
    if "T" in ts:
        try:
            return datetime.fromisoformat(ts).astimezone(timezone.utc)
        except ValueError:
            pass

    # Human-readable UTC  e.g. "2021-01-01 00:00:00 UTC"
    if ts.endswith(" UTC"):
        try:
            return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S %Z").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            pass

    # Syslog shortform  e.g. "Jun 10 14:23:01"  (no year)
    try:
        parsed = datetime.strptime(ts, "%b %d %H:%M:%S")
        return parsed.replace(
            year=datetime.now().year, tzinfo=timezone.utc
        )
    except ValueError:
        pass

    # Syslog with leading spaces  e.g. "Jun  5 08:01:00"
    try:
        parsed = datetime.strptime(ts, "%b  %d %H:%M:%S")
        return parsed.replace(
            year=datetime.now().year, tzinfo=timezone.utc
        )
    except ValueError:
        pass

    return None


def _brute_force_in_window(timestamps: list[datetime], window_sec: int) -> bool:
    """
    Return True if any sliding window of `window_sec` seconds contains
    >= _BRUTE_FORCE_THRESHOLD timestamps.
    """
    if len(timestamps) < _BRUTE_FORCE_THRESHOLD:
        return False
    sorted_ts = sorted(timestamps)
    for i in range(len(sorted_ts) - _BRUTE_FORCE_THRESHOLD + 1):
        delta = (sorted_ts[i + _BRUTE_FORCE_THRESHOLD - 1] - sorted_ts[i]).total_seconds()
        if delta <= window_sec:
            return True
    return False


# ── Main detector ──────────────────────────────────────────────────────────────

def detect_anomalies(logs: list[dict]) -> list[dict]:
    """
    Analyse a list of structured log entries and flag anomalies.

    Args:
        logs: List of structured log dicts from the parser.

    Returns:
        Same list with 'is_anomaly' (bool) and 'reason' (str) added to every
        entry. Input dicts are mutated in-place for efficiency.
    """

    # ── Pre-pass: build all frequency/time tables ─────────────────────────────

    # Rule 1 – failed logins per IP: raw count + parsed timestamps
    failed_login_counts: Counter = Counter()
    # IP → list of parsed datetime objects (None entries are skipped)
    failed_login_times: dict[str, list[datetime]] = defaultdict(list)

    for log in logs:
        if (
            log.get("log_type", "").lower() == "syslog"
            and "failed password" in log.get("event", "").lower()
        ):
            ip = log["source_ip"]
            failed_login_counts[ip] += 1
            parsed = _parse_timestamp(log.get("timestamp"))
            if parsed:
                failed_login_times[ip].append(parsed)

    # Rule 1 decision per IP: time-window path if we have enough timestamps,
    # otherwise fall back to raw count.
    brute_force_ips: set[str] = set()
    for ip, count in failed_login_counts.items():
        times = failed_login_times[ip]
        if len(times) >= _BRUTE_FORCE_THRESHOLD:
            # All timestamps parseable — use sliding-window check
            if _brute_force_in_window(times, _BRUTE_FORCE_WINDOW_SEC):
                brute_force_ips.add(ip)
        elif count >= _BRUTE_FORCE_THRESHOLD:
            # Timestamps missing or unparseable — fall back to raw count
            brute_force_ips.add(ip)

    # Rule 2 – VPC traffic volume per IP
    vpc_ip_counts: Counter = Counter()
    for log in logs:
        if log.get("log_type", "").lower() == "vpc_flow":
            vpc_ip_counts[log["source_ip"]] += 1

    # Rule 3 – repeated REJECTs in VPC logs
    reject_count: int = sum(
        1 for log in logs
        if log.get("log_type", "").lower() == "vpc_flow"
        and "reject" in log.get("event", "").upper()
    )
    has_repeated_rejects: bool = reject_count > 1

    # Rule 5 – linkDown trap count per IP
    linkdown_counts: Counter = Counter()
    for log in logs:
        if log.get("log_type", "").lower() != "snmp":
            continue
        trap_type = log.get("trap_type", "")
        event     = log.get("event", "")
        if trap_type.lower() == "linkdown" or "linkdown" in event.lower():
            linkdown_counts[log["source_ip"]] += 1

    # Rule 7 – firewall DENY count per IP
    fw_deny_counts: Counter = Counter()
    for log in logs:
        if (
            log.get("log_type", "").lower() == "firewall"
            and "DENY" in log.get("event", "").upper()
        ):
            fw_deny_counts[log["source_ip"]] += 1

    # Rule 8 – web 401 count per IP
    web_401_counts: Counter = Counter()
    for log in logs:
        if (
            log.get("log_type", "").lower() == "web"
            and "401" in log.get("event", "")
        ):
            web_401_counts[log["source_ip"]] += 1

    # ── Main pass: tag every log entry ────────────────────────────────────────
    for log in logs:
        anomaly_reasons: list[str] = []
        log_type = log.get("log_type", "").lower()
        event    = log.get("event", "")
        src_ip   = log.get("source_ip", "")

        # Rule 1 – Brute Force / Suspicious Login (Syslog)
        if log_type == "syslog" and "failed password" in event.lower():
            if src_ip in brute_force_ips:
                anomaly_reasons.append(
                    "Multiple failed login attempts (possible brute force attack)"
                )
            else:
                # Below brute-force threshold — still flag as suspicious
                anomaly_reasons.append(
                    "Single failed login attempt (suspicious)"
                )

        # Rule 2 – Traffic Spike (VPC)
        if log_type == "vpc_flow" and vpc_ip_counts[src_ip] > _VPC_SPIKE_THRESHOLD:
            anomaly_reasons.append(
                "High traffic volume detected from this IP"
            )

        # Rule 3 – Repeated REJECT Traffic (VPC)
        if (
            log_type == "vpc_flow"
            and "reject" in event.upper()
            and has_repeated_rejects
        ):
            anomaly_reasons.append(
                "Repeated rejected connections (possible scan or attack)"
            )

        # Rule 4 – SNMP Authentication Failure
        if "authenticationfailure" in event.lower():
            anomaly_reasons.append(
                "SNMP authentication failures detected"
            )

        # Rule 5 – SNMP Link Flapping
        if log_type == "snmp":
            trap_type   = log.get("trap_type", "")
            is_linkdown = (
                trap_type.lower() == "linkdown"
                or "linkdown" in event.lower()
            )
            if is_linkdown and linkdown_counts[src_ip] >= _LINKDOWN_FLAP_THRESHOLD:
                anomaly_reasons.append(
                    "Multiple linkDown events (possible link flapping)"
                )

        # Rule 6 – VPC packet/byte spike (single-entry threshold)
        if log_type == "vpc_flow":
            try:
                packets = int(log.get("packets", 0) or 0)
                bytes_  = int(log.get("bytes",   0) or 0)
            except (ValueError, TypeError):
                packets = bytes_ = 0
            if packets > _VPC_PACKET_THRESHOLD or bytes_ > _VPC_BYTE_THRESHOLD:
                anomaly_reasons.append(
                    "Unusual traffic spike detected"
                )

        # Rule 7 – Firewall port scan (repeated DENYs from same IP)
        if log_type == "firewall" and "DENY" in event.upper():
            if fw_deny_counts[src_ip] >= _FW_PORTSCAN_THRESHOLD:
                anomaly_reasons.append(
                    "Repeated denied connections (possible port scan)"
                )

        # Rule 8 – Web brute force (repeated HTTP 401s from same IP)
        if log_type == "web" and "401" in event:
            if web_401_counts[src_ip] >= _WEB_BRUTEFORCE_THRESHOLD:
                anomaly_reasons.append(
                    "Multiple unauthorized access attempts"
                )

        # Attach result fields
        if anomaly_reasons:
            log["is_anomaly"] = True
            log["reason"]     = "; ".join(anomaly_reasons)
        else:
            log["is_anomaly"] = False
            log["reason"]     = "Normal activity"

    return logs


# ── Self-test ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    sample = [
        # Rule 1 — Brute force (3 failures within 30 seconds)
        {"timestamp": "Jun 10 14:23:01", "source_ip": "10.0.0.1",
         "event": "Failed password for root from 10.0.0.1", "log_type": "syslog"},
        {"timestamp": "Jun 10 14:23:15", "source_ip": "10.0.0.1",
         "event": "Failed password for admin from 10.0.0.1", "log_type": "syslog"},
        {"timestamp": "Jun 10 14:23:30", "source_ip": "10.0.0.1",
         "event": "Failed password for user from 10.0.0.1", "log_type": "syslog"},
        # Rule 1 — Spread-out logins (>60 s apart) — should NOT be brute force
        {"timestamp": "Jun 10 08:00:00", "source_ip": "10.0.0.2",
         "event": "Failed password for root from 10.0.0.2", "log_type": "syslog"},
        {"timestamp": "Jun 10 08:02:00", "source_ip": "10.0.0.2",
         "event": "Failed password for root from 10.0.0.2", "log_type": "syslog"},
        {"timestamp": "Jun 10 08:04:00", "source_ip": "10.0.0.2",
         "event": "Failed password for root from 10.0.0.2", "log_type": "syslog"},
        # Rule 5 — Link flapping
        {"timestamp": None, "source_ip": "192.168.1.1",
         "event": "SNMP Trap: linkDown from 192.168.1.1",
         "trap_type": "linkDown", "log_type": "snmp"},
        {"timestamp": None, "source_ip": "192.168.1.1",
         "event": "SNMP Trap: linkDown from 192.168.1.1",
         "trap_type": "linkDown", "log_type": "snmp"},
        {"timestamp": None, "source_ip": "192.168.1.1",
         "event": "SNMP Trap: linkDown from 192.168.1.1",
         "trap_type": "linkDown", "log_type": "snmp"},
        # Normal syslog
        {"timestamp": "Jun 10 14:25:00", "source_ip": "192.168.1.5",
         "event": "Accepted password for deploy from 192.168.1.5", "log_type": "syslog"},
        # Rule 6 — VPC byte spike (bytes > 100000)
        {"timestamp": None, "source_ip": "10.1.1.1",
         "event": "Traffic ACCEPT from 10.1.1.1 to 10.0.1.5 on port 443 (TCP)",
         "log_type": "vpc_flow", "packets": "500", "bytes": "150000"},
        # Rule 6 — VPC packet spike (packets > 2000)
        {"timestamp": None, "source_ip": "10.1.1.2",
         "event": "Traffic ACCEPT from 10.1.1.2 to 10.0.1.5 on port 80 (TCP)",
         "log_type": "vpc_flow", "packets": "3000", "bytes": "5000"},
        # Rule 6 — Normal VPC (below both thresholds)
        {"timestamp": None, "source_ip": "10.1.1.3",
         "event": "Traffic ACCEPT from 10.1.1.3 to 10.0.1.5 on port 80 (TCP)",
         "log_type": "vpc_flow", "packets": "10", "bytes": "400"},
        # Rule 7 — Firewall port scan (3 DENYs from same IP)
        {"timestamp": None, "source_ip": "10.2.2.2",
         "event": "DENY TCP from 10.2.2.2 to 10.0.0.5 port 22", "log_type": "firewall"},
        {"timestamp": None, "source_ip": "10.2.2.2",
         "event": "DENY TCP from 10.2.2.2 to 10.0.0.5 port 80", "log_type": "firewall"},
        {"timestamp": None, "source_ip": "10.2.2.2",
         "event": "DENY TCP from 10.2.2.2 to 10.0.0.5 port 443", "log_type": "firewall"},
        # Rule 7 — Single DENY (below threshold — no anomaly)
        {"timestamp": None, "source_ip": "10.2.2.3",
         "event": "DENY TCP from 10.2.2.3 to 10.0.0.5 port 22", "log_type": "firewall"},
        # Rule 8 — Web brute force (2 × 401 from same IP)
        {"timestamp": None, "source_ip": "10.3.3.3",
         "event": "GET /admin HTTP/1.1 [HTTP 401]", "log_type": "web"},
        {"timestamp": None, "source_ip": "10.3.3.3",
         "event": "POST /login HTTP/1.1 [HTTP 401]", "log_type": "web"},
        # Rule 8 — Single 401 (below threshold — no anomaly)
        {"timestamp": None, "source_ip": "10.3.3.4",
         "event": "GET /secret HTTP/1.1 [HTTP 401]", "log_type": "web"},
    ]

    results = detect_anomalies(sample)
    print("=" * 70)
    print("  ANOMALY DETECTION SELF-TEST")
    print("=" * 70)
    for i, log in enumerate(results, 1):
        flag = "ANOMALY" if log["is_anomaly"] else "NORMAL "
        print(f"[{i:02d}] {flag} | {log['source_ip']:<16} | {log['reason']}")
    print("=" * 70)

    # ── Original assertions (unchanged) ──────────────────────────────────────
    assert results[0]["is_anomaly"] and "brute force" in results[0]["reason"].lower(), \
        "Fast brute force should be detected"
    assert not results[3]["is_anomaly"] or "brute force" not in results[3]["reason"].lower(), \
        "Slow spread-out logins should NOT be brute force"
    assert results[6]["is_anomaly"] and "link flapping" in results[6]["reason"].lower(), \
        "Link flapping should be detected"
    assert not results[9]["is_anomaly"], "Normal login should not be anomaly"

    # ── New assertions — Rule 6: VPC spike ───────────────────────────────────
    assert results[10]["is_anomaly"] and "traffic spike" in results[10]["reason"].lower(), \
        "VPC byte spike should be detected"
    assert results[11]["is_anomaly"] and "traffic spike" in results[11]["reason"].lower(), \
        "VPC packet spike should be detected"
    assert not results[12]["is_anomaly"], \
        "Normal VPC traffic should not be anomaly"

    # ── New assertions — Rule 7: Firewall port scan ───────────────────────────
    assert results[13]["is_anomaly"] and "port scan" in results[13]["reason"].lower(), \
        "3 DENYs from same IP should be flagged as port scan"
    assert not results[16]["is_anomaly"], \
        "Single DENY should not be flagged as port scan"

    # ── New assertions — Rule 8: Web brute force ─────────────────────────────
    assert results[17]["is_anomaly"] and "unauthorized" in results[17]["reason"].lower(), \
        "2+ HTTP 401s from same IP should be web brute force"
    assert not results[19]["is_anomaly"], \
        "Single HTTP 401 should not be flagged as brute force"

    print("  All assertions passed.")

