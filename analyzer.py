import re
from collections import Counter


def analyze_logs(file):

    with open(file, "r") as f:
        logs = f.readlines()


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


    timeline = []



    for log in logs:


        # Login success

        if "LOGIN SUCCESS" in log:
            success += 1
            severity["low"] += 1



        # Failed login

        if "LOGIN FAILED" in log:

            failed += 1
            severity["medium"] += 1



        # Extract user

        user = re.search(
            r"User:\s(\w+)",
            log
        )


        if user:

            username = user.group(1)

            users.append(username)


            if "LOGIN FAILED" in log:

                failed_users.append(username)



        # Extract IP

        ip = re.search(
            r"IP:\s([\d.]+)",
            log
        )


        if ip:

            address = ip.group(1)

            ips.append(address)


            if "LOGIN FAILED" in log:

                failed_ips.append(address)



        # Example timeline data

        time = re.search(
            r"\[(.*?)\]",
            log
        )

        if time:

            timeline.append(
                time.group(1)
            )




    # Detect suspicious users


    suspicious = []


    for user, count in Counter(failed_users).items():


        if count >= 3:


            suspicious.append(
                {
                    "user": user,
                    "attempts": count,
                    "level": "HIGH"
                }
            )


            severity["high"] += 1




    # Detect suspicious IPs


    suspicious_ips = []


    for ip, count in Counter(failed_ips).items():


        if count >= 3:


            suspicious_ips.append(
                {
                    "ip": ip,
                    "attempts": count,
                    "risk": "HIGH"
                }
            )




    # Calculate threat score


    threat_score = 0


    if failed > 0:

        threat_score += 30


    if len(suspicious) > 0:

        threat_score += 30


    if len(suspicious_ips) > 0:

        threat_score += 30


    if threat_score > 100:

        threat_score = 100





    # Threat count

    threats = (
        len(suspicious)
        +
        len(suspicious_ips)
    )




    return {


        # Old values (keep compatibility)

        "total": len(logs),

        "success": success,

        "failed": failed,

        "users": len(set(users)),

        "ips": len(set(ips)),

        "suspicious": suspicious,



        # Dashboard values


        "total_logs": len(logs),

        "threat_score": threat_score,

        "threats": threats,


        "failed_logins": failed,


        "suspicious_ips": suspicious_ips,


        "alerts": suspicious,



        "severity": severity,


        "timeline": timeline

    }