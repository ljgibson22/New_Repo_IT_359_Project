from collections import defaultdict
from sklearn.ensemble import IsolationForest

def run_ai_detection(logs):
    failed_counts = defaultdict(int)
    login_hours = defaultdict(list)

    for log in logs:
        ip = log["ip"]
        login_hours[ip].append(log["hour"])

        if log["status"] == "failed":
            failed_counts[ip] += 1

    ip_list = list(login_hours.keys())
    features = []

    for ip in ip_list:
        avg_hour = sum(login_hours[ip]) / len(login_hours[ip])
        features.append([failed_counts[ip], avg_hour])

    if len(features) < 2:
        return {}

    model = IsolationForest(contamination=0.3, random_state=42)
    model.fit(features)

    predictions = model.predict(features)

    ai_results = {}
    for i, ip in enumerate(ip_list):
        ai_results[ip] = int(predictions[i])

    return ai_results
