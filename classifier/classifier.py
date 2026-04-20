"""
classifier/classifier.py
------------------------
Severity classifier for parsed + anomaly-tagged log entries.

Maps anomaly reasons and log metadata to a human-readable severity level:
  CRITICAL  – active brute force, SNMP auth failure
  HIGH      – traffic spike, repeated rejects
  MEDIUM    – single suspicious login attempt
  LOW       – flagged but low confidence
  INFO      – fully normal, no anomalies

Reason strings are matched against the exact phrases produced by
detect_anomalies() in detection/anomaly_detector.py. Keep these in sync
if detector reason strings ever change.
"""


def classify_log(log: dict) -> str:
    """
    Determine the severity of a single log entry.

    Args:
        log: A structured log dict, expected to have 'is_anomaly' and 'reason'
             fields (as produced by detect_anomalies).

    Returns:
        A severity string: "CRITICAL", "HIGH", "MEDIUM", "LOW", or "INFO".
    """
    if not log.get("is_anomaly", False):
        return "INFO"

    reason = log.get("reason", "").lower()

    # CRITICAL — active brute-force or device-level auth failure
    # Matches: "multiple failed login attempts (possible brute force attack)"
    # Matches: "snmp authentication failures detected"
    if "brute force" in reason or "authentication failures" in reason:
        return "CRITICAL"

    # HIGH — network-level threats with repeated patterns
    # Matches: "high traffic volume detected from this ip"
    # Matches: "repeated rejected connections (possible scan or attack)"
    # Matches: "multiple linkdown events (possible link flapping)"
    if "high traffic volume" in reason or "repeated rejected" in reason or "link flapping" in reason:
        return "HIGH"

    # MEDIUM — single suspicious login (below brute-force threshold)
    # Matches: "single failed login attempt (suspicious)"
    if "single failed login" in reason:
        return "MEDIUM"

    # LOW — anomaly flagged but reason doesn't match a known pattern
    return "LOW"
