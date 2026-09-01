#!/usr/bin/env python3

import os

LOG_FILE = "zeek-logs/conn.log"
REPORT_FILE = "reports/traffic_report.txt"

if not os.path.exists(LOG_FILE):
    print("Error: conn.log not found")
    exit(1)

os.makedirs("reports", exist_ok=True)

fields = []
connections = []

with open(LOG_FILE, "r") as f:
    for line in f:
        line = line.strip()

        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue

        if line.startswith("#") or not line:
            continue

        values = line.split("\t")

        if fields and len(values) == len(fields):
            connections.append(dict(zip(fields, values)))

suspicious_ports = {
    "21": "FTP",
    "23": "Telnet",
    "445": "SMB",
    "3389": "RDP",
    "4444": "Common testing port"
}

high_risk = []
normal = []

for conn in connections:

    destination = conn.get("id.resp_p", "-")
    protocol = conn.get("proto", "-")

    if destination in suspicious_ports:
        high_risk.append(conn)

    elif protocol in ["tcp", "udp"] and destination not in [
        "21", "22", "23", "25", "53", "80",
        "443", "445", "8080", "3389"
    ]:
        high_risk.append(conn)

    else:
        normal.append(conn)

with open(REPORT_FILE, "w") as report:

    report.write("NETWORK TRAFFIC ANALYSIS REPORT\n")
    report.write("=" * 45 + "\n\n")

    report.write(f"Total connections: {len(connections)}\n")
    report.write(f"Normal connections: {len(normal)}\n")
    report.write(f"Suspicious connections: {len(high_risk)}\n\n")

    report.write("TRAFFIC DETAILS\n")
    report.write("-" * 45 + "\n")

    for conn in connections:

        src = conn.get("id.orig_h", "-")
        dst = conn.get("id.resp_h", "-")
        port = conn.get("id.resp_p", "-")
        proto = conn.get("proto", "-")
        service = conn.get("service", "-")

        status = "NORMAL"

        if port in suspicious_ports:
            status = "SUSPICIOUS - " + suspicious_ports[port]

        elif proto in ["tcp", "udp"] and port not in [
            "21", "22", "23", "25", "53", "80",
            "443", "445", "8080", "3389"
        ]:
            status = "UNUSUAL PORT"

        report.write(
            f"{src} -> {dst}:{port} | "
            f"Protocol: {proto} | "
            f"Service: {service} | "
            f"Status: {status}\n"
        )

    report.write("\nSECURITY SUMMARY\n")
    report.write("-" * 45 + "\n")

    if high_risk:
        report.write("Potentially unusual traffic was detected.\n")
    else:
        report.write("No suspicious ports were detected.\n")

print("Analysis completed successfully!")
print(f"Total connections: {len(connections)}")
print(f"Normal connections: {len(normal)}")
print(f"Suspicious connections: {len(high_risk)}")
print(f"Report saved to: {REPORT_FILE}")
