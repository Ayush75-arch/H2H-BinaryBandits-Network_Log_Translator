"""
pipeline.py  (v7 — Advanced Intelligence Edition)
"""
import logging
import time
from collections import defaultdict, Counter
from typing import Any

from parser.log_parser          import parse_log
from detection.anomaly_detector import detect_anomalies
from classifier.classifier      import classify_log
from summarizer.llm_summarizer  import generate_batch_explanation, generate_explanation

logger = logging.getLogger(__name__)
_SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def _detect_compromises(logs):
    host_failed = defaultdict(set)
    host_accepted = defaultdict(set)
    for log in logs:
        if log.get("log_type") != "syslog":
            continue
        event = log.get("event", "").lower()
        src = log.get("source_ip", "unknown")
        host = log.get("host", "unknown")
        if "failed password" in event:
            host_failed[host].add(src)
        elif "accepted password" in event or "accepted publickey" in event:
            host_accepted[host].add(src)
    compromised_ips = set()
    for host, failed_set in host_failed.items():
        if host_accepted.get(host):
            compromised_ips |= failed_set
    return compromised_ips


def _build_timelines(logs):
    per_ip = defaultdict(list)
    for log in logs:
        ip = log.get("source_ip", "unknown")
        per_ip[ip].append({
            "time": log.get("timestamp", ""),
            "event": log.get("event", log.get("reason", "Unknown event")),
            "severity": log.get("severity", "INFO"),
            "log_type": log.get("log_type", "unknown"),
            "is_anomaly": log.get("is_anomaly", False),
        })
    for ip in per_ip:
        per_ip[ip].sort(key=lambda e: e.get("time") or "")
    return per_ip


def _classify_attack_chain(ip_logs, is_compromised):
    stages = []
    reasons = {}
    has_recon = any("port scan" in l.get("reason","").lower() or
                    "repeated rejected" in l.get("reason","").lower() or
                    (l.get("log_type") == "firewall" and l.get("is_anomaly"))
                    for l in ip_logs)
    has_intrusion = any("brute force" in l.get("reason","").lower() or
                        "failed login" in l.get("reason","").lower()
                        for l in ip_logs)
    has_post = any("high traffic" in l.get("reason","").lower() or
                   "traffic spike" in l.get("reason","").lower() or
                   "authentication failures" in l.get("reason","").lower()
                   for l in ip_logs)
    if has_recon:
        stages.append("Recon")
        reasons["Recon"] = "Port scans / repeated connection denials"
    if has_intrusion:
        stages.append("Intrusion")
        reasons["Intrusion"] = "Brute-force SSH login attempts"
    if is_compromised:
        stages.append("Compromise")
        reasons["Compromise"] = "Successful authentication after failures"
    if has_post and (is_compromised or has_intrusion):
        stages.append("Post-Compromise")
        reasons["Post-Compromise"] = "High-volume outbound traffic detected"
    if "Compromise" in stages and "Post-Compromise" in stages:
        final = "Potential Compromise + Data Exfiltration"
    elif "Compromise" in stages:
        final = "Account Compromise"
    elif "Intrusion" in stages and "Recon" in stages:
        final = "Targeted Intrusion Attempt"
    elif "Intrusion" in stages:
        final = "Brute-Force Attack"
    elif "Recon" in stages:
        final = "Reconnaissance"
    else:
        final = "Anomalous Activity"
    return {"stages": stages, "stage_reasons": reasons, "final_classification": final}


def _compute_scores(ip_logs, is_compromised, attack_chain):
    anomaly_count  = sum(1 for l in ip_logs if l.get("is_anomaly"))
    critical_count = sum(1 for l in ip_logs if l.get("severity") == "CRITICAL")
    high_count     = sum(1 for l in ip_logs if l.get("severity") == "HIGH")
    stage_count    = len(attack_chain.get("stages", []))
    base_conf = min(40 + anomaly_count*5 + critical_count*10 + stage_count*8, 97)
    confidence = min(base_conf + (10 if is_compromised else 0), 99)
    base_risk = min(30 + critical_count*15 + high_count*8 + stage_count*10, 95)
    risk = base_risk
    if is_compromised and "Post-Compromise" in attack_chain.get("stages", []):
        risk = 100
    elif is_compromised:
        risk = max(risk, 92)
    elif stage_count >= 3:
        risk = max(risk, 85)
    return int(confidence), int(risk)


def _advanced_explanation(log, confidence):
    """
    SOC-grade 3-part explanation: [Pattern]. [Threat meaning]. [Impact + action].
    Each explanation is 2-3 sentences covering WHAT happened, WHY it matters, and WHAT to do.
    """
    reason    = log.get("reason", "").lower()
    severity  = log.get("severity", "INFO")
    src_ip    = log.get("source_ip", "unknown")
    log_type  = log.get("log_type", "unknown")
    raw_reason = log.get("reason", "Unknown")

    if "brute force" in reason:
        return (
            f"Repeated failed SSH login attempts from {src_ip} within a 60-second window exceed the brute-force threshold (>=3 failures/min), indicating an automated credential stuffing or dictionary attack. "
            f"This pattern is a direct precursor to account compromise -- attackers systematically exhaust common passwords until authentication succeeds. "
            f"Immediately block {src_ip} at the firewall, lock affected accounts, and enable multi-factor authentication to prevent unauthorized access (Confidence: {confidence}%)."
        )
    if "single failed login" in reason:
        return (
            f"A single failed SSH authentication attempt was observed from external host {src_ip}, which did not meet the automated brute-force threshold. "
            f"While isolated failures can indicate mistyped credentials, external sources that fail authentication are indicators of opportunistic probing or early-stage reconnaissance. "
            f"Monitor {src_ip} for repeat attempts and cross-correlate with firewall and VPC logs to determine if broader scanning activity is underway (Confidence: {confidence}%)."
        )
    if "high traffic volume" in reason:
        return (
            f"Source {src_ip} generated more than 5 simultaneous VPC flow connections, exceeding normal baseline thresholds for this network segment. "
            f"Elevated outbound connection counts are consistent with data exfiltration staging, C2 beaconing, or deployment of scanning tools against internal targets. "
            f"Isolate {src_ip} from outbound internet access, capture flow telemetry for forensic analysis, and escalate to IR if data sensitivity is high (Confidence: {confidence}%)."
        )
    if "traffic spike" in reason:
        return (
            f"An extreme spike in packet and byte volume was detected in a single VPC flow originating from {src_ip}, far exceeding normal throughput baselines. "
            f"High-volume single-flow anomalies indicate bulk data transfers, network flooding, or active exfiltration of large datasets to an external destination. "
            f"Rate-limit or block {src_ip} immediately, preserve full packet capture for forensic review, and investigate what data was potentially transferred (Confidence: {confidence}%)."
        )
    if "repeated rejected" in reason:
        return (
            f"Multiple REJECT entries in VPC flow logs from {src_ip} across consecutive connection attempts indicate systematic port or service probing. "
            f"Repeated rejections across varying destination ports are a hallmark of automated port scanning -- the attacker is mapping open services for subsequent exploitation. "
            f"Block {src_ip} at the perimeter, review which ports were probed, and verify no connections succeeded that may indicate service exposure (Confidence: {confidence}%)."
        )
    if "authentication failures" in reason and log_type == "snmp":
        return (
            f"SNMP authentication failure traps were received from {src_ip}, indicating repeated attempts to access network device management interfaces with invalid credentials or community strings. "
            f"Unauthorized SNMP access would grant an attacker full visibility into network topology, device configs, and routing tables -- critical reconnaissance data for targeted attacks. "
            f"Restrict SNMP access via ACLs to trusted management IPs only, rotate community strings immediately, and investigate whether {src_ip} has probed other management interfaces (Confidence: {confidence}%)."
        )
    if "link flapping" in reason:
        return (
            f"Three or more linkDown SNMP traps were received from {src_ip} in rapid succession, indicating repeated physical or logical interface instability. "
            f"Link flapping at this frequency suggests either a failing hardware component, a misconfigured link, or deliberate physical-layer disruption targeting network availability. "
            f"Dispatch a network engineer to inspect the affected interface, review STP logs for topology changes, and determine if the instability is hardware failure or deliberate interference (Confidence: {confidence}%)."
        )
    if "port scan" in reason:
        return (
            f"Three or more firewall DENY events from {src_ip} targeting different destination ports were detected, consistent with an automated port scan using tools such as nmap or masscan. "
            f"Active port scanning is a reconnaissance technique used to identify exploitable services -- it directly precedes targeted exploitation attempts against discovered open ports. "
            f"Block {src_ip} at the edge firewall, review which ports were targeted for open service exposure, and verify IDS/IPS signatures are current for detected scan patterns (Confidence: {confidence}%)."
        )
    if "unauthorized" in reason:
        return (
            f"Multiple HTTP 401 Unauthorized responses were generated for requests from {src_ip}, indicating repeated failed authentication attempts against a web application endpoint. "
            f"Sustained 401 patterns from a single source are a strong indicator of credential brute-forcing or credential stuffing attacks targeting user accounts on the application. "
            f"Implement IP-based rate limiting on the authentication endpoint, enable account lockout policies, and consider CAPTCHA enforcement to block automated login attacks (Confidence: {confidence}%)."
        )
    if not log.get("is_anomaly"):
        return (
            f"Normal {log_type} traffic was observed from {src_ip} with no anomalous patterns detected against baseline behavioral models. "
            f"This activity falls within expected parameters and does not match any known threat signatures or statistical anomaly thresholds. "
            f"No immediate action required -- continue standard monitoring and retain logs per data retention policy."
        )
    return (
        f"Anomalous {severity.lower()} activity was detected from {src_ip} in {log_type} logs matching the pattern: {raw_reason}. "
        f"This event deviates from established behavioral baselines and has been flagged for analyst review -- the specific pattern may indicate an emerging or novel threat vector. "
        f"Investigate {src_ip} activity across all log sources, correlate with threat intelligence feeds, and escalate if additional indicators of compromise are found (Confidence: {confidence}%)."
    )


def _build_attack_summary(log):
    """
    Generate a concise kill-chain style attack_summary field.
    Format: "Stage 1 -> Stage 2 -> Stage 3"
    Based on reason, severity, log_type, and anomaly/compromise status.
    """
    reason   = log.get("reason", "").lower()
    severity = log.get("severity", "INFO")
    log_type = log.get("log_type", "unknown")
    is_comp  = log.get("is_compromised", False)

    if not log.get("is_anomaly"):
        return "Normal activity -- no attack chain identified"

    if is_comp:
        return "Brute-force attack -> credential compromise -> unauthorized access achieved"

    if "brute force" in reason:
        return "Credential brute-force -> repeated authentication failures -> account lockout risk"

    if "port scan" in reason or "repeated rejected" in reason:
        return "Network reconnaissance -> port scanning -> service discovery -> targeted exploitation risk"

    if "high traffic volume" in reason or "traffic spike" in reason:
        if severity in ("CRITICAL", "HIGH"):
            return "Anomalous outbound volume -> data staging -> potential exfiltration"
        return "Traffic anomaly -> bandwidth abuse -> DDoS staging or bulk transfer"

    if "authentication failures" in reason and log_type == "snmp":
        return "SNMP probing -> management interface targeting -> network topology reconnaissance"

    if "link flapping" in reason:
        return "Interface instability -> network disruption -> availability impact"

    if "unauthorized" in reason:
        return "Web credential attack -> authentication bypass attempt -> application account compromise risk"

    if "single failed login" in reason:
        return "Opportunistic probing -> failed authentication -> low-confidence reconnaissance"

    if severity == "CRITICAL":
        return "Critical anomaly detected -> immediate threat indicator -> urgent analyst review required"
    if severity == "HIGH":
        return "High-severity anomaly -> active threat behavior -> escalation recommended"
    if severity == "MEDIUM":
        return "Suspicious activity -> behavioral deviation -> monitoring and investigation required"

    return "Anomalous pattern detected -> threat indicator -> analyst review recommended"


def _correlate_incidents(logs):
    ip_anomaly_count = Counter()
    ip_anomaly_types = defaultdict(set)
    for log in logs:
        if not log.get("is_anomaly"):
            continue
        ip = log.get("source_ip", "unknown")
        ip_anomaly_count[ip] += 1
        ip_anomaly_types[ip].add(log.get("log_type", "unknown"))
    incident_ips = {ip for ip, cnt in ip_anomaly_count.items()
                    if cnt >= 2 or len(ip_anomaly_types[ip]) >= 2}
    for log in logs:
        ip = log.get("source_ip", "unknown")
        if log.get("is_anomaly") and ip in incident_ips:
            log["incident"]        = True
            log["incident_reason"] = "Multiple related anomalies from same source IP"
        else:
            log["incident"]        = False
            log["incident_reason"] = ""
    return logs


def _build_incidents(logs, timelines, compromised_ips):
    ip_logs = defaultdict(list)
    for log in logs:
        ip_logs[log.get("source_ip","unknown")].append(log)
    incident_ips = {l["source_ip"] for l in logs if l.get("incident")}
    incidents = []
    for ip in incident_ips:
        ip_l     = ip_logs[ip]
        is_comp  = ip in compromised_ips
        chain    = _classify_attack_chain(ip_l, is_comp)
        conf, risk = _compute_scores(ip_l, is_comp, chain)
        max_sev  = max(ip_l, key=lambda l: _SEV_ORDER.get(l.get("severity","INFO"),1))
        if is_comp:
            fail_cnt = sum(1 for l in ip_l if "failed password" in l.get("event","").lower())
            explanation = (f"Account compromise detected: {ip} made {fail_cnt} failed login attempts "
                           f"followed by a successful authentication. Chain: {' → '.join(chain['stages'])}. "
                           f"Confidence: {conf}%, Risk: {risk}/100.")
            incident_type = "COMPROMISED_ACCOUNT"
        else:
            explanation = (f"{chain['final_classification']} from {ip}: {len(ip_l)} events across "
                           f"{len(set(l.get('log_type') for l in ip_l))} log types. "
                           f"Chain: {' → '.join(chain['stages']) if chain['stages'] else 'Single-stage'}. "
                           f"Confidence: {conf}%, Risk: {risk}/100.")
            incident_type = chain["final_classification"].upper().replace(" ","_").replace("+","AND")
        incidents.append({
            "ip": ip, "severity": max_sev.get("severity","HIGH"),
            "confidence_score": conf, "risk_score": risk,
            "incident_type": incident_type, "is_compromised": is_comp,
            "explanation": explanation, "attack_chain": chain,
            "timeline": timelines.get(ip, []),
            "event_count": len(ip_l),
            "attack_summary": _build_attack_summary(max_sev),
            "log_types": list(set(l.get("log_type","unknown") for l in ip_l)),
            "events": [{"severity": l.get("severity","INFO"), "log_type": l.get("log_type","unknown"),
                        "reason": l.get("reason",""), "source_ip": l.get("source_ip","unknown"),
                        "timestamp": l.get("timestamp")} for l in ip_l],
        })
    incidents.sort(key=lambda i: i["risk_score"], reverse=True)
    return incidents


def _build_recommendations(incidents, top_severity):
    recs = []
    has_compromise = any(i.get("is_compromised") for i in incidents)
    has_critical   = top_severity == "CRITICAL"
    has_high       = top_severity in ("CRITICAL","HIGH")
    if has_compromise or has_critical:
        recs += [
            {"action":"Block source IP immediately",              "urgency":"CRITICAL","icon":"🚫"},
            {"action":"Force password reset for affected accounts","urgency":"CRITICAL","icon":"🔐"},
            {"action":"Escalate to security team now",            "urgency":"CRITICAL","icon":"📣"},
        ]
    if has_high:
        recs += [
            {"action":"Preserve logs for forensic analysis",      "urgency":"HIGH",    "icon":"📋"},
            {"action":"Review firewall rules for affected ports",  "urgency":"HIGH",    "icon":"🛡️"},
        ]
    if incidents:
        recs += [
            {"action":"Monitor source IPs for further activity",  "urgency":"MEDIUM",  "icon":"👁️"},
            {"action":"Update IDS/IPS signatures",                "urgency":"MEDIUM",  "icon":"🔧"},
        ]
    if not recs:
        recs = [{"action":"No action required — normal activity","urgency":"INFO","icon":"✅"}]
    return recs


# ── Public API ────────────────────────────────────────────────────────────────

def process_logs(raw_logs):
    start = time.time()
    parsed_logs = []
    for raw in raw_logs:
        if raw and isinstance(raw, str) and raw.strip():
            p = parse_log(raw)
            if p:
                parsed_logs.append(p)
    if not parsed_logs:
        return {"summary":"No recognisable logs found.","time_to_clarity":f"{round(time.time()-start,3)} sec",
                "logs":[],"incidents":[],"recommended_actions":[],"anomaly_count":0,"incident_count":0}
    enriched = detect_anomalies(parsed_logs)
    for e in enriched:
        e["severity"] = classify_log(e)
    enriched = _correlate_incidents(enriched)
    compromised_ips = _detect_compromises(enriched)
    timelines = _build_timelines(enriched)
    ip_logs = defaultdict(list)
    for e in enriched:
        ip_logs[e.get("source_ip","unknown")].append(e)
    for e in enriched:
        ip = e.get("source_ip","unknown")
        ip_l = ip_logs[ip]
        is_comp = ip in compromised_ips
        chain = _classify_attack_chain(ip_l, is_comp)
        conf, risk = _compute_scores(ip_l, is_comp, chain)
        e["confidence_score"] = conf
        e["risk_score"]       = risk
        e["explanation"]      = _advanced_explanation(e, conf)
        e["is_compromised"]   = is_comp and e.get("is_anomaly", False)
        e["attack_summary"]   = _build_attack_summary(e)
    incidents = _build_incidents(enriched, timelines, compromised_ips)
    summary = generate_batch_explanation(enriched)
    top_sev = max(enriched, key=lambda l: _SEV_ORDER.get(l.get("severity","INFO"),1), default={})
    top_severity = top_sev.get("severity","INFO") if top_sev else "INFO"
    recs = _build_recommendations(incidents, top_severity)
    log_results = []
    for e in enriched:
        log_results.append({
            "severity": e["severity"], "is_anomaly": e.get("is_anomaly",False),
            "reason": e.get("reason",""),
            "explanation": e.get("explanation",""),
            "confidence_score": e.get("confidence_score",50), "risk_score": e.get("risk_score",0),
            "source_ip": e.get("source_ip","unknown"), "timestamp": e.get("timestamp"),
            "log_type": e.get("log_type","unknown"),
            "incident": e.get("incident",False), "incident_reason": e.get("incident_reason",""),
            "is_compromised": e.get("is_compromised",False),
            "attack_summary": e.get("attack_summary",""),
        })
    return {
        "summary": summary, "time_to_clarity": f"{round(time.time()-start,3)} sec",
        "logs": log_results, "incidents": incidents, "recommended_actions": recs,
        "anomaly_count": sum(1 for e in enriched if e.get("is_anomaly")),
        "incident_count": len(incidents),
    }


def process_log(raw_log):
    start = time.time()
    if not raw_log or not isinstance(raw_log, str) or not raw_log.strip():
        return {"error":"Invalid log: input must be a non-empty string."}
    parsed = parse_log(raw_log)
    if not parsed:
        return {"error":"Invalid log: unrecognised format."}
    enriched = detect_anomalies([parsed])[0]
    enriched["severity"]         = classify_log(enriched)
    enriched["incident"]         = False
    enriched["incident_reason"]  = ""
    enriched["is_compromised"]   = False
    enriched["confidence_score"] = 50 if enriched.get("is_anomaly") else 10
    enriched["risk_score"]       = 30 if enriched.get("severity") == "CRITICAL" else 15
    enriched["explanation"]      = _advanced_explanation(enriched, enriched["confidence_score"])
    enriched["attack_summary"]    = _build_attack_summary(enriched)
    explanation = generate_explanation(enriched)
    return {
        "severity": enriched["severity"], "is_anomaly": enriched.get("is_anomaly",False),
        "reason": enriched.get("reason",""),
        "explanation": explanation or enriched["explanation"],
        "attack_summary": enriched["attack_summary"],
        "confidence_score": enriched["confidence_score"], "risk_score": enriched["risk_score"],
        "source_ip": enriched.get("source_ip","unknown"), "timestamp": enriched.get("timestamp"),
        "log_type": enriched.get("log_type","unknown"),
        "incident": False, "incident_reason": "", "is_compromised": False,
        "time_to_clarity": f"{round(time.time()-start,3)} sec",
    }
