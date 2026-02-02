#!/usr/bin/env python3

import argparse
import re
from collections import defaultdict
from datetime import datetime

# ----------------------------
# Regex patterns (generic auth logs)
# ----------------------------
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FAILED_KEYWORDS = [
    "failed password",
    "authentication failure",
    "invalid user",
    "login failed"
]

# ----------------------------
# Functions
# ----------------------------
def is_failed_login(line: str) -> bool:
    """Check if a log line represents a failed login attempt."""
    line_lower = line.lower()
    return any(keyword in line_lower for keyword in FAILED_KEYWORDS)


def extract_ip(line: str):
    """Extract IP address from a log line."""
    match = IP_PATTERN.search(line)
    return match.group() if match else None


def analyze_log(file_path: str, threshold: int):
    failed_attempts = defaultdict(int)

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as log_file:
            for line in log_file:
                if is_failed_login(line):
                    ip = extract_ip(line)
                    if ip:
                        failed_attempts[ip] += 1
    except FileNotFoundError:
        print(f"[!] File not found: {file_path}")
        return

    print("\n=== Security Log Analysis Report ===")
    print(f"Analyzed file: {file_path}")
    print(f"Timestamp: {datetime.now()}")
    print("-----------------------------------")

    suspicious_found = False

    for ip, count in sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True):
        print(f"IP: {ip} | Failed attempts: {count}")
        if count >= threshold:
            suspicious_found = True

    print("-----------------------------------")
    if suspicious_found:
        print(f"[!] Suspicious IPs detected (threshold: {threshold}+ attempts)")
    else:
        print("[✓] No suspicious activity detected")


# ----------------------------
# Main
# ----------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer - Detect failed login attacks"
    )
    parser.add_argument(
        "logfile",
        help="Path to the log file to analyze"
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=5,
        help="Number of failed attempts to flag an IP (default: 5)"
    )

    args = parser.parse_args()
    analyze_log(args.logfile, args.threshold)


if __name__ == "__main__":
    main()
