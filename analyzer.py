import re
import os
import csv
from collections import defaultdict
import matplotlib.pyplot as plt

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "logs", "sample_logs.txt")
THREAT_REPORT = os.path.join(BASE_DIR, "detected_threats.txt")
CSV_REPORT = os.path.join(BASE_DIR, "detected_threats.csv")
CHART_FILE = os.path.join(BASE_DIR, "threat_chart.png")

# Threat Counters
brute_force_total = 0
sql_total = 0
admin_total = 0

# Storage
failed_login_count = defaultdict(int)
admin_access_count = defaultdict(int)
detected_rows = []

# Read logs
with open(LOG_FILE, "r") as file:
    logs = file.readlines()

# -------------------------------
# Brute Force Detection
# -------------------------------
for line in logs:
    if "Failed login" in line:
        ip_match = re.search(r"\d+\.\d+\.\d+\.\d+", line)
        if ip_match:
            ip = ip_match.group()
            failed_login_count[ip] += 1

for ip, count in failed_login_count.items():
    if count >= 3:
        brute_force_total += 1
        detected_rows.append(
            ["Brute Force", ip, count, "HIGH"]
        )

# -------------------------------
# SQL Injection Detection
# -------------------------------
sql_keywords = [
    "UNION SELECT",
    "OR 1=1",
    "DROP TABLE"
]

for line in logs:
    for keyword in sql_keywords:
        if keyword.lower() in line.lower():
            ip_match = re.search(r"\d+\.\d+\.\d+\.\d+", line)
            ip = ip_match.group() if ip_match else "Unknown"

            sql_total += 1
            detected_rows.append(
                ["SQL Injection", ip, keyword, "HIGH"]
            )

# -------------------------------
# Suspicious Admin Access Detection
# -------------------------------
for line in logs:
    if "/admin" in line:
        ip_match = re.search(r"\d+\.\d+\.\d+\.\d+", line)
        if ip_match:
            ip = ip_match.group()
            admin_access_count[ip] += 1

for ip, count in admin_access_count.items():
    if count >= 2:
        admin_total += 1
        detected_rows.append(
            ["Suspicious Admin Access", ip, count, "MEDIUM"]
        )

# -------------------------------
# Write Text Threat Report
# -------------------------------
with open(THREAT_REPORT, "w") as report:
    report.write("DETECTED CYBERSECURITY THREATS\n")
    report.write("=" * 40 + "\n\n")

    for row in detected_rows:
        report.write(f"Attack Type: {row[0]}\n")
        report.write(f"IP Address: {row[1]}\n")
        report.write(f"Details: {row[2]}\n")
        report.write(f"Severity: {row[3]}\n")
        report.write("-" * 30 + "\n")

print("Threat analysis completed successfully.")

# -------------------------------
# Write CSV Report
# -------------------------------
with open(CSV_REPORT, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Attack Type", "IP Address", "Details", "Severity"])
    writer.writerows(detected_rows)

print("CSV report generated.")

# -------------------------------
# Generate Threat Statistics Chart
# -------------------------------
labels = ["Brute Force", "SQL Injection", "Admin Access"]
values = [brute_force_total, sql_total, admin_total]

plt.figure()
plt.bar(labels, values)
plt.xlabel("Threat Type")
plt.ylabel("Count")
plt.title("Threat Statistics")
plt.savefig(CHART_FILE)
plt.close()

print("Threat statistics chart generated.")
