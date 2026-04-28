from parser import parse_logs
from detection import detect_threats
from ai_model import run_ai_detection
from reports import generate_report, save_report

logs = parse_logs("logs/sample.log")
threats = detect_threats(logs)
ai_results = run_ai_detection(logs)
report = generate_report(threats, ai_results)

print("\n===== Incident Response Log Analyzer Report =====\n")

for item in report:
    print(f"IP Address: {item['ip']}")
    print(f"Severity: {item['severity']}")
    print(f"AI Anomaly Detected: {item['ai_anomaly']}")
    print("Reasons:")
    for reason in item["reasons"]:
        print(f"- {reason}")
    print("----------------------------------------")

save_report(report)
print("\nReport saved to incident_report.json")
