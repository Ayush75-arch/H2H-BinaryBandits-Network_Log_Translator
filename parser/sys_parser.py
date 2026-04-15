import re
import json


def parse_syslog(log: str) -> dict | None:
    """
    Parse a syslog-formatted string and extract timestamp, source IP, and event.
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
    remainder_pattern = r'^\s+\S+\s+\S+?:\s*(?P<message>.+)$'
    rem_match = re.match(remainder_pattern, remainder, re.DOTALL)

    if rem_match:
        message = rem_match.group("message").strip()
    else:
        message = remainder.strip()

    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_match = re.search(ip_pattern, message)
    source_ip = ip_match.group() if ip_match else "unknown"

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "event": message
    }


# ✅ INTEGRATION BLOCK (ADDED)

if __name__ == "__main__":
    print("=" * 60)
    print("  Syslog Parser — File Test")
    print("=" * 60)

    try:
        with open("logs/syslog.log", "r") as f:
            logs = f.readlines()
    except FileNotFoundError:
        print("❌ ERROR: logs/syslog.log not found")
        exit()

    for i, log in enumerate(logs, start=1):
        print(f"\n[Log {i}] Raw input:")
        print(f"  {log.strip()}")

        result = parse_syslog(log)

        if result is None:
            print("  ⚠ Result: Unable to parse")
        else:
            print("  ✔ Parsed:")
            print("  " + json.dumps(result, indent=4).replace("\n", "\n  "))

    print("\n" + "=" * 60)