"""
tests/test_pipeline.py
----------------------
Minimal test suite for the Network Log Translator pipeline.

Run with:
    cd network-log-translator
    python -m pytest tests/ -v
    # or without pytest:
    python tests/test_pipeline.py
"""

import sys
import os

# Allow imports from the project root regardless of working directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline import process_log, process_logs


# ── Helpers ───────────────────────────────────────────────────────────────────

def _brute_force_batch() -> list[str]:
    """Three SSH failures from the same IP within 30 seconds."""
    return [
        "Jun 10 14:23:01 webserver01 sshd[1]: Failed password for root from 10.0.0.9 port 1001",
        "Jun 10 14:23:15 webserver01 sshd[1]: Failed password for admin from 10.0.0.9 port 1002",
        "Jun 10 14:23:30 webserver01 sshd[1]: Failed password for user from 10.0.0.9 port 1003",
    ]


# ── Test 1: Single failed login → anomaly flagged ─────────────────────────────

def test_single_failed_login_is_anomaly():
    """A single SSH failed-password event should be flagged as an anomaly."""
    log = "Jun 10 14:23:01 webserver01 sshd[1]: Failed password for root from 10.0.0.1 port 58321"
    result = process_log(log)

    assert "error" not in result, f"Unexpected error: {result.get('error')}"
    assert result["is_anomaly"] is True, "Single failed login should be an anomaly"
    assert result["severity"] in {"MEDIUM", "HIGH", "CRITICAL"}, (
        f"Expected elevated severity, got {result['severity']}"
    )
    assert "time_to_clarity" in result, "time_to_clarity must be present"
    print("  PASS  test_single_failed_login_is_anomaly")


# ── Test 2: 3 rapid failed logins → CRITICAL brute force ─────────────────────

def test_brute_force_is_critical():
    """Three failed logins within 60 s from same IP → CRITICAL brute force."""
    result = process_logs(_brute_force_batch())

    assert result["logs"], "Batch result should contain log entries"
    for entry in result["logs"]:
        assert entry["is_anomaly"] is True, (
            f"All entries should be anomalies, got: {entry['reason']}"
        )
        assert entry["severity"] == "CRITICAL", (
            f"Brute force should be CRITICAL, got {entry['severity']}"
        )
        assert "brute force" in entry["reason"].lower(), (
            f"Reason should mention brute force: {entry['reason']}"
        )
    print("  PASS  test_brute_force_is_critical")


# ── Test 3: Normal accepted login → no anomaly ────────────────────────────────

def test_normal_login_is_not_anomaly():
    """A successful accepted login should not be flagged as an anomaly."""
    log = "Jun 10 14:23:06 webserver01 sshd[1]: Accepted password for deploy from 192.168.1.5 port 22"
    result = process_log(log)

    assert "error" not in result, f"Unexpected error: {result.get('error')}"
    assert result["is_anomaly"] is False, (
        f"Normal login should not be anomaly, reason: {result['reason']}"
    )
    assert result["severity"] == "INFO", (
        f"Normal login should be INFO severity, got {result['severity']}"
    )
    print("  PASS  test_normal_login_is_not_anomaly")


# ── Test 4: SNMP auth failure → CRITICAL ─────────────────────────────────────

def test_snmp_auth_failure_is_critical():
    """SNMP authenticationFailure should be detected and rated CRITICAL."""
    log = "SNMP Trap: authenticationFailure from 10.10.10.1"
    result = process_log(log)

    assert "error" not in result, f"Unexpected error: {result.get('error')}"
    assert result["is_anomaly"] is True, "SNMP auth failure must be an anomaly"
    assert result["severity"] == "CRITICAL", (
        f"SNMP auth failure should be CRITICAL, got {result['severity']}"
    )
    print("  PASS  test_snmp_auth_failure_is_critical")


# ── Test 5: SNMP link flapping → HIGH anomaly ─────────────────────────────────

def test_snmp_link_flapping_is_high():
    """Three linkDown traps from the same IP → HIGH link flapping anomaly."""
    logs = [
        "SNMP Trap: linkDown from 192.168.1.1",
        "SNMP Trap: linkDown from 192.168.1.1",
        "SNMP Trap: linkDown from 192.168.1.1",
    ]
    result = process_logs(logs)

    assert result["logs"], "Should return log entries"
    for entry in result["logs"]:
        assert entry["is_anomaly"] is True, "linkDown flapping should be anomaly"
        assert entry["severity"] == "HIGH", (
            f"Link flapping should be HIGH, got {entry['severity']}"
        )
        assert "link flapping" in entry["reason"].lower(), (
            f"Reason should mention link flapping: {entry['reason']}"
        )
    print("  PASS  test_snmp_link_flapping_is_high")


# ── Test 6: Incident correlation ──────────────────────────────────────────────

def test_incident_correlation():
    """
    An IP that generates brute-force anomalies across multiple log entries
    should have incident=True on all its anomalous entries.
    """
    result = process_logs(_brute_force_batch())

    assert result["logs"], "Should return log entries"
    for entry in result["logs"]:
        assert entry["incident"] is True, (
            f"Brute force entries from same IP should be correlated incidents"
        )
        assert entry["incident_reason"] != "", (
            "incident_reason should not be empty for correlated incidents"
        )
    print("  PASS  test_incident_correlation")


# ── Test 7: Batch response structure ─────────────────────────────────────────

def test_batch_response_structure():
    """Batch response must have summary, time_to_clarity, and logs keys."""
    logs = [
        "Jun 10 14:23:01 webserver01 sshd[1]: Failed password for root from 10.0.0.1 port 1",
        "SNMP Trap: linkDown from 192.168.1.1",
    ]
    result = process_logs(logs)

    assert "summary" in result,         "Batch result must have 'summary'"
    assert "time_to_clarity" in result, "Batch result must have 'time_to_clarity'"
    assert "logs" in result,            "Batch result must have 'logs'"
    assert isinstance(result["logs"], list), "'logs' must be a list"

    for entry in result["logs"]:
        assert "explanation" not in entry, (
            "Individual log entries must NOT contain 'explanation' (lives in summary)"
        )
    print("  PASS  test_batch_response_structure")


# ── Test 8: time_to_clarity format ────────────────────────────────────────────

def test_time_to_clarity_format():
    """time_to_clarity must be a non-empty string ending with ' sec'."""
    log = "Jun 10 14:23:01 webserver01 sshd[1]: Accepted password for user from 10.0.0.1 port 22"
    result = process_log(log)

    ttc = result.get("time_to_clarity", "")
    assert isinstance(ttc, str) and ttc.endswith("sec"), (
        f"time_to_clarity format wrong: {ttc!r}"
    )
    print("  PASS  test_time_to_clarity_format")


# ── Test 9: Unrecognised log → error returned gracefully ──────────────────────

def test_unrecognised_log_returns_error():
    """Garbage input should return an error dict, not raise an exception."""
    result = process_log("this is not a valid log line %%%")
    assert "error" in result, "Unrecognised log should return an error key"
    print("  PASS  test_unrecognised_log_returns_error")


# ── Runner (no pytest required) ───────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_single_failed_login_is_anomaly,
        test_brute_force_is_critical,
        test_normal_login_is_not_anomaly,
        test_snmp_auth_failure_is_critical,
        test_snmp_link_flapping_is_high,
        test_incident_correlation,
        test_batch_response_structure,
        test_time_to_clarity_format,
        test_unrecognised_log_returns_error,
    ]

    print("=" * 60)
    print("  Network Log Translator — Test Suite")
    print("=" * 60)
    passed = failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR {test.__name__}: {e}")
            failed += 1

    print("=" * 60)
    print(f"  Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)
