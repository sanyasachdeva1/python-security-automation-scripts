import sys
import re
from collections import defaultdict


def detect_failed_logins(log_file, threshold=3):
    failed_login_pattern = re.compile(
        r"Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    failed_attempts = defaultdict(int)

    with open(log_file, "r") as file:
        for line in file:
            match = failed_login_pattern.search(line)
            if match:
                ip = match.group("ip")
                failed_attempts[ip] += 1

    print("\nSecurity Finding: Failed Login Analysis")
    print("-" * 45)

    suspicious_found = False

    for ip, count in failed_attempts.items():
        if count >= threshold:
            suspicious_found = True
            print(f"[HIGH] Suspicious IP: {ip}")
            print(f"      Failed login attempts: {count}")
            print("      Possible brute-force activity detected.\n")

    if not suspicious_found:
        print("No suspicious failed login activity detected.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/log_anomaly_detector.py sample-data/auth.log")
        sys.exit(1)

    detect_failed_logins(sys.argv[1])
