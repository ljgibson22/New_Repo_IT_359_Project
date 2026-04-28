import json

def generate_report(threats, ai_results):
    final_report = {}

    for threat in threats:
        ip = threat["ip"]

        if ip not in final_report:
            final_report[ip] = {
                "ip": ip,
                "severity": threat["severity"],
                "reasons": set(threat["reasons"]),
                "ai_anomaly": False
            }

        final_report[ip]["reasons"].update(threat["reasons"])

    for ip, prediction in ai_results.items():
        if prediction == -1:
            if ip not in final_report:
                final_report[ip] = {
                    "ip": ip,
                    "severity": "Medium",
                    "reasons": set(),
                    "ai_anomaly": True
                }

            final_report[ip]["ai_anomaly"] = True
            final_report[ip]["reasons"].add("AI anomaly detected")

            if final_report[ip]["severity"] in ["Medium", "Low"]:
                final_report[ip]["severity"] = "High"

    for ip in final_report:
        final_report[ip]["reasons"] = list(final_report[ip]["reasons"])

    return list(final_report.values())


def save_report(report, filename="incident_report.json"):
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
