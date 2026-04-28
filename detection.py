from collections import defaultdict

def detect_threats(logs):
    failed_counts = defaultdict(int)
    threats = []

    # Count failed login attempts by IP
    for log in logs:
        if log["status"] == "failed":
            failed_counts[log["ip"]] += 1

    # Apply detection rules
    for log in logs:
        ip = log["ip"]
        reasons = []
        severity = "Low"

        if failed_counts[ip] >= 3:
            reasons.append("Possible brute-force attack")
            severity = "High"

        if 2 <= log["hour"] <= 4:
            reasons.append("Unusual login time")
            if severity != "High":
                severity = "Medium"

        if reasons:
            threats.append({
                "ip": ip,
                "status": log["status"],
                "hour": log["hour"],
                "severity": severity,
                "reasons": reasons
            })

    return threats
