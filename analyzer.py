import re
import csv
from datetime import datetime
from collections import defaultdict

log_file_path = "logs/sample_logs.txt"
text_output_path = "detected_threats.txt"
csv_output_path = "detected_threats.csv"

# -------------------------------
# Read Logs
# -------------------------------
with open(log_file_path, "r") as file:
    logs = file.readlines()

threats_text = []
threats_csv = []

# -------------------------------
# Helpers
# -------------------------------
def extract_timestamp(line):
    try:
        return datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")
    except:
        return None

def extract_ip(line):
    match = re.search(r"\d+\.\d+\.\d+\.\d+", line)
    return match.group() if match else None

# -------------------------------
# Brute Force Detection (Time-based)
# Rule: ≥3 failed logins within 2 minutes
# -------------------------------
failed_logins = defaultdict(list)

for line in logs:
    if "Failed login" in line:
        ip = extract_ip(line)
        ts = extract_timestamp(line)
        if ip and ts:
            failed_logins[ip].append(ts)

for ip, timestamps in failed_logins.items():
    timestamps.sort()
    if len(timestamps) >= 3:
        time_diff = (timestamps[-1] - timestamps[0]).seconds
        if time_diff <= 120:  # 2 minutes
            severity = "HIGH" if len(timestamps) >= 5 else "MEDIUM"
            threats_text.append(
                f"Brute Force Attack | IP: {ip} | Attempts: {len(timestamps)} | Time Window: {time_diff}s | Severity: {severity}"
            )
            threats_csv.append(
                ["Brute Force Attack", ip, len(timestamps), f"{time_diff}s", severity]
            )

# -------------------------------
# SQL Injection Detection
# -------------------------------
sql_keywords = ["UNION SELECT", "OR 1=1", "DROP TABLE"]

for line in logs:
    for keyword in sql_keywords:
        if keyword.lower() in line.lower():
            ip = extract_ip(line)
            ts = extract_timestamp(line)
            threats_text.append(
                f"SQL Injection Attempt | IP: {ip} | Time: {ts} | Keyword: {keyword} | Severity: HIGH"
            )
            threats_csv.append(
                ["SQL Injection", ip, keyword, ts, "HIGH"]
            )

# -------------------------------
# Admin Access Detection (Time-based)
# Rule: ≥2 accesses within 1 minute
# -------------------------------
admin_access = defaultdict(list)

for line in logs:
    if "/admin" in line:
        ip = extract_ip(line)
        ts = extract_timestamp(line)
        if ip and ts:
            admin_access[ip].append(ts)

for ip, timestamps in admin_access.items():
    timestamps.sort()
    if len(timestamps) >= 2:
        time_diff = (timestamps[-1] - timestamps[0]).seconds
        if time_diff <= 60:
            severity = "HIGH" if len(timestamps) >= 4 else "MEDIUM"
            threats_text.append(
                f"Suspicious Admin Access | IP: {ip} | Attempts: {len(timestamps)} | Time Window: {time_diff}s | Severity: {severity}"
            )
            threats_csv.append(
                ["Admin Access", ip, len(timestamps), f"{time_diff}s", severity]
            )

# -------------------------------
# Write Text Output
# -------------------------------
with open(text_output_path, "w") as file:
    file.write("DETECTED CYBERSECURITY THREATS (TIME-BASED)\n")
    file.write("=" * 45 + "\n\n")
    for t in threats_text:
        file.write(t + "\n")

# -------------------------------
# Write CSV Output
# -------------------------------
with open(csv_output_path, "w", newline="") as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(["Attack_Type", "IP", "Count/Keyword", "Time_Window/Time", "Severity"])
    for row in threats_csv:
        writer.writerow(row)

print("Threat analysis with timestamps completed successfully.")
