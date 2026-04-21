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
    reason   = log.get("reason", "").lower()
    severity = log.get("severity", "INFO")
    src_ip   = log.get("source_ip", "unknown")
    log_type = log.get("log_type", "unknown")

    if "brute force" in reason:
        return (f"Multiple failed SSH login attempts from {src_ip} within 60s exceed the brute-force "
                f"threshold (≥3/min). High-probability automated credential attack. Confidence: {confidence}%")
    if "single failed login" in reason:
        return (f"Single failed SSH authentication from {src_ip}. Below brute-force threshold, "
                f"but external failure should be monitored. Confidence: {confidence}%")
    if "high traffic volume" in reason:
        return (f"{src_ip} generated >5 VPC flow connections — possible exfiltration, DDoS staging, "
                f"or scan tool. Confidence: {confidence}%")
    if "traffic spike" in reason:
        return (f"Extreme packet/byte volume in single VPC flow from {src_ip}. "
                f"Possible bulk data transfer or flood. Confidence: {confidence}%")
    if "repeated rejected" in reason:
        return (f"Multiple REJECT VPC entries from {src_ip} — consistent with port scanning "
                f"or service probing. Confidence: {confidence}%")
    if "authentication failures" in reason and log_type == "snmp":
        return (f"SNMP auth failure trap from {src_ip}. Indicates unauthorized device "
                f"management attempt or misconfigured NMS. Confidence: {confidence}%")
    if "link flapping" in reason:
        return (f"≥3 linkDown traps from {src_ip} in rapid succession. Possible hardware "
                f"failure or deliberate network disruption. Confidence: {confidence}%")
    if "port scan" in reason:
        return (f"≥3 firewall DENYs from {src_ip} across different ports — automated port "
                f"scan probing for open services. Confidence: {confidence}%")
    if "unauthorized" in reason:
        return (f"Multiple HTTP 401s from {src_ip} — web credential brute-force attempt "
                f"against authentication endpoint. Confidence: {confidence}%")
    if not log.get("is_anomaly"):
        return f"Normal {log_type} traffic from {src_ip}. No suspicious patterns detected."
    return (f"Anomalous {severity.lower()} activity from {src_ip} in {log_type} logs. "
            f"Reason: {log.get('reason','Unknown')}. Confidence: {confidence}%")


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
    incidents = _build_incidents(enriched, timelines, compromised_ips)
    summary = generate_batch_explanation(enriched)
    top_sev = max(enriched, key=lambda l: _SEV_ORDER.get(l.get("severity","INFO"),1), default={})
    top_severity = top_sev.get("severity","INFO") if top_sev else "INFO"
    recs = _build_recommendations(incidents, top_severity)
    log_results = []
    for e in enriched:
        log_results.append({
            "severity": e["severity"], "is_anomaly": e.get("is_anomaly",False),
            "reason": e.get("reason",""), "explanation": e.get("explanation",""),
            "confidence_score": e.get("confidence_score",50), "risk_score": e.get("risk_score",0),
            "source_ip": e.get("source_ip","unknown"), "timestamp": e.get("timestamp"),
            "log_type": e.get("log_type","unknown"),
            "incident": e.get("incident",False), "incident_reason": e.get("incident_reason",""),
            "is_compromised": e.get("is_compromised",False),
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
    explanation = generate_explanation(enriched)
    return {
        "severity": enriched["severity"], "is_anomaly": enriched.get("is_anomaly",False),
        "reason": enriched.get("reason",""),
        "explanation": explanation or enriched["explanation"],
        "confidence_score": enriched["confidence_score"], "risk_score": enriched["risk_score"],
        "source_ip": enriched.get("source_ip","unknown"), "timestamp": enriched.get("timestamp"),
        "log_type": enriched.get("log_type","unknown"),
        "incident": False, "incident_reason": "", "is_compromised": False,
        "time_to_clarity": f"{round(time.time()-start,3)} sec",
    }
