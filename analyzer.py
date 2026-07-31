import re
from collections import Counter
from datetime import datetime

# Matches a leading "2026-07-28 09:10:15" or "2026-07-28T09:10:15" style timestamp
TIMESTAMP_RE = re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")
# Fallback: a timestamp wrapped in brackets, e.g. "[28/Jul/2026:09:10:15]"
BRACKET_RE = re.compile(r"\[(.*?)\]")

TIMESTAMP_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S")


def _parse_timestamp(log):
    """Best-effort extraction of a real datetime from a single log line."""
    match = TIMESTAMP_RE.search(log)
    candidate = match.group(1) if match else None

    if candidate is None:
        bracket = BRACKET_RE.search(log)
        if bracket:
            inner = TIMESTAMP_RE.search(bracket.group(1))
            candidate = inner.group(1) if inner else None

    if candidate is None:
        return None

    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(candidate.replace("T", " "), fmt.replace("T", " "))
        except ValueError:
            continue
    return None


def _format_seen(dt):
    if dt is None:
        return "Unknown"
    if dt.date() == datetime.now().date():
        return "Today, " + dt.strftime("%I:%M %p").lstrip("0")
    return dt.strftime("%b %d, %I:%M %p").replace(" 0", " ")


def analyze_logs(file, high_threshold=3, medium_threshold=2):
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

    hourly_counts = [0] * 24
    parsed_timestamps = []          # every datetime we could parse, in file order
    event_types = Counter()
    critical_event_rows = []
    ip_last_seen = {}                # ip -> most recent datetime seen (any event)
    line_index_for_fallback = 0      # used only if the file has no parsable timestamps at all

    for log in logs:
        normalized = log.upper()
        dt = _parse_timestamp(log)

        if dt is not None:
            parsed_timestamps.append(dt)
            hourly_counts[dt.hour] += 1
        else:
            # No real timestamp on this line - still make sure it contributes
            # to the timeline so the chart reflects the whole file.
            hourly_counts[line_index_for_fallback % 24] += 1
        line_index_for_fallback += 1

        if "CRITICAL" in normalized:
            severity["critical"] += 1
            critical_event_rows.append({
                "title": log[:72].rstrip(" ."),
                "time": _format_seen(dt),
                "_dt": dt
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
            if dt is not None and (address not in ip_last_seen or dt > ip_last_seen[address]):
                ip_last_seen[address] = dt
            if "LOGIN FAILED" in normalized:
                failed_ips.append(address)

    suspicious_users = []
    for user, count in Counter(failed_users).items():
        level = "HIGH" if count >= high_threshold else "MEDIUM"
        suspicious_users.append({
            "user": user,
            "attempts": count,
            "level": level
        })

    suspicious_ip_rows = []
    for ip, count in Counter(failed_ips).items():
        if count == 0:
            continue
        risk = "high" if count >= high_threshold else "medium" if count >= medium_threshold else "low"
        suspicious_ip_rows.append({
            "ip": ip,
            "country": "Unknown",
            "risk": risk,
            "events": count,
            "seen": _format_seen(ip_last_seen.get(ip))
        })
        # A brute-force pattern (high_threshold+ failed attempts from one IP) is a
        # real critical event, even if the log never literally says "CRITICAL".
        if count >= high_threshold:
            severity["critical"] += 1
            critical_event_rows.append({
                "title": "Possible brute-force attack from " + ip + " (" + str(count) + " failed attempts)",
                "time": _format_seen(ip_last_seen.get(ip)),
                "_dt": ip_last_seen.get(ip)
            })
        elif count >= medium_threshold:
            severity["high"] += 1

    if not suspicious_ip_rows and ips:
        suspicious_ip_rows.append({
            "ip": ips[0],
            "country": "Unknown",
            "risk": "low",
            "events": 1,
            "seen": _format_seen(ip_last_seen.get(ips[0]))
        })

    if not critical_event_rows and failed > 0:
        critical_event_rows.append({
            "title": "Multiple failed login attempts detected",
            "time": _format_seen(parsed_timestamps[-1] if parsed_timestamps else None),
            "_dt": parsed_timestamps[-1] if parsed_timestamps else None
        })

    # Most recent events first; entries without a timestamp sort last.
    critical_event_rows.sort(key=lambda r: r.get("_dt") or datetime.min, reverse=True)
    for row in critical_event_rows:
        row.pop("_dt", None)
    critical_event_rows = critical_event_rows[:8]

    total_events = len(logs)
    threat_score = 0
    if failed > 0:
        threat_score += 25
    if len(suspicious_users) > 0:
        threat_score += 25
    if len(suspicious_ip_rows) > 0:
        threat_score += 25
    if severity["critical"] > 0:
        threat_score += 25
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
        "timeline": hourly_counts,
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
