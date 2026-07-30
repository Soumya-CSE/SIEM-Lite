import re
from collections import Counter


def analyze_logs(file):
    if isinstance(file, str):
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            logs = [line.strip() for line in f if line.strip()]
    elif hasattr(file, 'read'):
        raw = file.read()
        if isinstance(raw, bytes):
            raw = raw.decode('utf-8', 'ignore')
        logs = [line.strip() for line in raw.splitlines() if line.strip()]
    elif isinstance(file, (bytes, bytearray)):
        text = file.decode('utf-8', 'ignore')
        logs = [line.strip() for line in text.splitlines() if line.strip()]
    else:
        logs = [line.strip() for line in file if line.strip()]

    success = 0
    failed = 0

    users = []
    ips = []

    failed_users = []
    failed_ips = []

    severity = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    raw_timestamps = []
    timeline = []
    event_types = Counter()
    critical_event_rows = []

    for log in logs:
        normalized = log.upper()
        timestamp = None

        time_match = re.search(r"\[(.*?)\]", log)
        if time_match:
            timestamp = time_match.group(1)
            raw_timestamps.append(timestamp)
            timeline.append(len(raw_timestamps) * 10)

        if "CRITICAL" in normalized:
            severity["critical"] += 1
            critical_event_rows.append({
                "title": log[:72].rstrip(" ."),
                "time": timestamp or "Unknown"
            })

        if "LOGIN SUCCESS" in normalized:
            success += 1
            severity["low"] += 1
            event_types["Auth Events"] += 1
        elif "LOGIN FAILED" in normalized:
            failed += 1
            severity["medium"] += 1
            event_types["Auth Events"] += 1
        elif "SSH" in normalized or "VPN" in normalized or "NETWORK" in normalized or "IP:" in normalized:
            event_types["Network Events"] += 1
        elif "ACCESS" in normalized or "FILE" in normalized or "READ" in normalized or "WRITE" in normalized:
            event_types["Access Events"] += 1
        else:
            event_types["System Events"] += 1

        user_match = re.search(r"User:\s(\w+)", log)
        if user_match:
            username = user_match.group(1)
            users.append(username)
            if "LOGIN FAILED" in normalized:
                failed_users.append(username)

        ip_match = re.search(r"IP:?\s*([\d.]+)", log)
        if ip_match:
            address = ip_match.group(1)
            ips.append(address)
            if "LOGIN FAILED" in normalized:
                failed_ips.append(address)

    suspicious_users = []
    for user, count in Counter(failed_users).items():
        level = "HIGH" if count >= 3 else "MEDIUM"
        suspicious_users.append({
            "user": user,
            "attempts": count,
            "level": level
        })
        if count >= 3:
            severity["high"] += 1

    suspicious_ip_rows = []
    for ip, count in Counter(failed_ips).items():
        if count == 0:
            continue
        risk = "high" if count >= 3 else "medium" if count == 2 else "low"
        suspicious_ip_rows.append({
            "ip": ip,
            "country": "Unknown",
            "risk": risk,
            "events": count,
            "seen": timeline[-1] if timeline else "Recent"
        })

    if not suspicious_ip_rows and ips:
        suspicious_ip_rows.append({
            "ip": ips[0],
            "country": "Unknown",
            "risk": "low",
            "events": 1,
            "seen": timeline[-1] if timeline else "Recent"
        })

    if not critical_event_rows and failed > 0:
        critical_event_rows.append({
            "title": "Multiple failed login attempts detected",
            "time": timeline[-1] if timeline else "Unknown"
        })

    total_events = len(logs)
    threat_score = 0
    if failed > 0:
        threat_score += 30
    if len(suspicious_users) > 0:
        threat_score += 30
    if len(suspicious_ip_rows) > 0:
        threat_score += 30
    if severity["critical"] > 0:
        threat_score += 10
    threat_score = min(threat_score, 100)

    severity_list = [
        {"name": "Critical", "value": severity["critical"], "color": "#fb4a5b"},
        {"name": "High", "value": severity["high"], "color": "#ff9d42"},
        {"name": "Medium", "value": severity["medium"], "color": "#ffd23f"},
        {"name": "Low", "value": severity["low"], "color": "#4a8dff"}
    ]

    return {
        "total": total_events,
        "success": success,
        "failed": failed,
        "users": len(set(users)),
        "ips": len(set(ips)),
        "suspicious": suspicious_users,
        "total_logs": total_events,
        "threat_score": threat_score,
        "threats": len(suspicious_users) + len(suspicious_ip_rows),
        "failed_logins": failed,
        "suspicious_ips": suspicious_ip_rows,
        "alerts": suspicious_users,
        "severity": severity_list,
        "timeline": timeline,
        "threatScore": threat_score,
        "failedLogins": failed,
        "suspiciousIps": len(suspicious_ip_rows),
        "criticalEvents": severity["critical"],
        "totalEvents": total_events,
        "eventTypes": [
            {"name": "Auth Events", "value": event_types.get("Auth Events", 0)},
            {"name": "System Events", "value": event_types.get("System Events", 0)},
            {"name": "Network Events", "value": event_types.get("Network Events", 0)},
            {"name": "Access Events", "value": event_types.get("Access Events", 0)}
        ],
        "suspiciousIpRows": suspicious_ip_rows,
        "criticalEventRows": critical_event_rows
    }
