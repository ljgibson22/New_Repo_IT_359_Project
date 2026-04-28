import re

def parse_logs(file_path):
    parsed_logs = []

    with open(file_path, "r") as file:
        for line in file:
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            time_match = re.search(r'\w+\s+\d+\s+(\d+):\d+:\d+', line)

            if ip_match and time_match:
                ip = ip_match.group(1)
                hour = int(time_match.group(1))

                if "Failed password" in line:
                    status = "failed"
                elif "Accepted password" in line:
                    status = "success"
                else:
                    status = "unknown"

                parsed_logs.append({
                    "ip": ip,
                    "status": status,
                    "hour": hour
                })

    return parsed_logs
