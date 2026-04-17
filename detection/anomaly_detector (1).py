"""
anomaly_detector.py
-------------------
Rule-based cybersecurity log anomaly detection engine.
"""

from collections import Counter


def detect_anomalies(logs: list[dict]) -> list[dict]:
    """
    Analyze a list of structured log entries and flag anomalies based on
    predefined security rules.

    Rules applied:
      1. Brute Force Detection     — >3 failed SSH logins from the same source IP
      2. Traffic Spike Detection   — source IP appears >5 times in VPC logs
      3. Suspicious REJECT Traffic — multiple REJECT events in VPC logs
      4. SNMP Auth Failure         — event contains 'authenticationFailure'

    Args:
        logs: List of structured log dicts (see module docstring for schema).

    Returns:
        The same list with 'is_anomaly' (bool) and 'reason' (str) added to
        every entry. Input dicts are mutated in-place; the list is also
        returned for convenience.
    """
    # ------------------------------------------------------------------ #
    # Pre-pass: build frequency tables needed for multi-log rules          #
    # ------------------------------------------------------------------ #

    # Rule 1 – count "Failed password" events per source IP (Syslog only)
    failed_login_counts: Counter = Counter()
    for log in logs:
        if (
            log.get("log_type", "").lower() == "syslog"
            and "failed password" in log.get("event", "").lower()
        ):
            failed_login_counts[log["source_ip"]] += 1

    # Rule 2 – count total appearances of each source IP in VPC logs
    vpc_ip_counts: Counter = Counter()
    for log in logs:
        if log.get("log_type", "").lower() == "vpc_flow":
            vpc_ip_counts[log["source_ip"]] += 1

    # Rule 3 – count REJECT events in VPC logs
    reject_count: int = sum(
        1
        for log in logs
        if log.get("log_type", "").lower() == "vpc_flow"
        and "reject" in log.get("event", "").upper()
    )
    has_repeated_rejects: bool = reject_count > 1

    # ------------------------------------------------------------------ #
    # Main pass: tag every log entry                                        #
    # ------------------------------------------------------------------ #
    for log in logs:
        anomaly_reasons: list[str] = []
        log_type = log.get("log_type", "").lower()
        event    = log.get("event", "")
        src_ip   = log.get("source_ip", "")

        # Rule 1 – Brute Force (Syslog)
        if (
            log_type == "syslog"
            and "failed password" in event.lower()
            and failed_login_counts[src_ip] > 3
        ):
            anomaly_reasons.append(
                "Multiple failed login attempts (possible brute force attack)"
            )

        # Rule 2 – Traffic Spike (VPC)
        if log_type == "vpc_flow" and vpc_ip_counts[src_ip] > 5:
            anomaly_reasons.append(
                "High traffic volume detected from this IP"
            )

        # Rule 3 – Suspicious REJECT Traffic (VPC)
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

        # Attach result fields
        if anomaly_reasons:
            log["is_anomaly"] = True
            log["reason"]     = "; ".join(anomaly_reasons)
        else:
            log["is_anomaly"] = False
            log["reason"]     = "Normal activity"

    return logs


# ====================================================================== #
# Test Block                                                               #
# ====================================================================== #
if __name__ == "__main__":
    import json

    sample_logs: list[dict] = [
        # --- Brute Force candidates (5 failed logins from 192.168.1.10) ---
        {
            "timestamp": "2024-01-15T08:01:00Z", "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.5", "port": "22", "protocol": "TCP",
            "event": "Failed password for root from 192.168.1.10",
            "log_type": "syslog",
        },
        {
            "timestamp": "2024-01-15T08:01:15Z", "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.5", "port": "22", "protocol": "TCP",
            "event": "Failed password for admin from 192.168.1.10",
            "log_type": "syslog",
        },
        {
            "timestamp": "2024-01-15T08:01:30Z", "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.5", "port": "22", "protocol": "TCP",
            "event": "Failed password for user from 192.168.1.10",
            "log_type": "syslog",
        },
        {
            "timestamp": "2024-01-15T08:01:45Z", "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.5", "port": "22", "protocol": "TCP",
            "event": "Failed password for ubuntu from 192.168.1.10",
            "log_type": "syslog",
        },
        {
            "timestamp": "2024-01-15T08:02:00Z", "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.5", "port": "22", "protocol": "TCP",
            "event": "Failed password for deploy from 192.168.1.10",
            "log_type": "syslog",
        },

        # --- Normal syslog (only 2 failures — below threshold) ---
        {
            "timestamp": "2024-01-15T08:05:00Z", "source_ip": "10.0.1.20",
            "destination_ip": "10.0.0.5", "port": "22", "protocol": "TCP",
            "event": "Failed password for guest from 10.0.1.20",
            "log_type": "syslog",
        },
        {
            "timestamp": "2024-01-15T08:05:30Z", "source_ip": "10.0.1.20",
            "destination_ip": "10.0.0.5", "port": "22", "protocol": "TCP",
            "event": "Failed password for guest from 10.0.1.20",
            "log_type": "syslog",
        },

        # --- Traffic Spike candidates (203.0.113.5 appears 7 times in VPC) ---
        *[
            {
                "timestamp": f"2024-01-15T09:0{i}:00Z",
                "source_ip": "203.0.113.5",
                "destination_ip": "172.16.0.1",
                "port": "443",
                "protocol": "TCP",
                "event": "ACCEPT",
                "log_type": "vpc_flow",
            }
            for i in range(7)
        ],

        # --- REJECT Traffic (3 entries → has_repeated_rejects = True) ---
        {
            "timestamp": "2024-01-15T09:10:00Z", "source_ip": "198.51.100.9",
            "destination_ip": "172.16.0.2", "port": "3389", "protocol": "TCP",
            "event": "REJECT", "log_type": "vpc_flow",
        },
        {
            "timestamp": "2024-01-15T09:10:05Z", "source_ip": "198.51.100.9",
            "destination_ip": "172.16.0.2", "port": "445", "protocol": "TCP",
            "event": "REJECT", "log_type": "vpc_flow",
        },
        {
            "timestamp": "2024-01-15T09:10:10Z", "source_ip": "198.51.100.9",
            "destination_ip": "172.16.0.2", "port": "8080", "protocol": "TCP",
            "event": "REJECT", "log_type": "vpc_flow",
        },

        # --- SNMP Authentication Failure ---
        {
            "timestamp": "2024-01-15T10:00:00Z", "source_ip": "10.10.10.1",
            "destination_ip": "10.10.10.254", "port": "161", "protocol": "UDP",
            "event": "authenticationFailure from 10.10.10.1",
            "log_type": "snmp",
        },

        # --- Normal VPC log (low-volume IP) ---
        {
            "timestamp": "2024-01-15T11:00:00Z", "source_ip": "192.0.2.50",
            "destination_ip": "172.16.0.3", "port": "80", "protocol": "TCP",
            "event": "ACCEPT", "log_type": "vpc_flow",
        },
    ]

    results = detect_anomalies(sample_logs)

    # Pretty-print results
    print("=" * 70)
    print("  ANOMALY DETECTION REPORT")
    print("=" * 70)

    anomaly_count = 0
    for idx, log in enumerate(results, start=1):
        status = "🚨 ANOMALY" if log["is_anomaly"] else "✅ NORMAL "
        print(f"\n[{idx:02d}] {status} | {log['timestamp']}")
        print(f"      src={log['source_ip']:<18} dst={log['destination_ip']}")
        print(f"      port={log['port']:<6} proto={log['protocol']:<5} "
              f"type={log['log_type']}")
        print(f"      event  : {log['event']}")
        print(f"      reason : {log['reason']}")
        if log["is_anomaly"]:
            anomaly_count += 1

    print("\n" + "=" * 70)
    print(f"  Total logs   : {len(results)}")
    print(f"  Anomalies    : {anomaly_count}")
    print(f"  Normal       : {len(results) - anomaly_count}")
    print("=" * 70)
