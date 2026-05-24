import argparse
import re
from collections import Counter, defaultdict
from pathlib import Path

try:
    from soc_common import Finding, add_common_output_args, emit_results, existing_file
except ModuleNotFoundError:
    from scripts.soc_common import Finding, add_common_output_args, emit_results, existing_file


FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?P<user>invalid user \S+|\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)
ACCEPTED_LOGIN_PATTERN = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def analyze_failed_logins(log_file, threshold=3):
    failed_attempts = defaultdict(list)
    targeted_users = defaultdict(Counter)
    accepted_logins = defaultdict(int)

    with Path(log_file).open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                ip = match.group("ip")
                user = match.group("user").replace("invalid user ", "")
                failed_attempts[ip].append(line_number)
                targeted_users[ip][user] += 1
                continue

            accepted_match = ACCEPTED_LOGIN_PATTERN.search(line)
            if accepted_match:
                accepted_logins[accepted_match.group("ip")] += 1

    findings = []

    for ip, lines in failed_attempts.items():
        failed_count = len(lines)
        if failed_count < threshold:
            continue

        severity = "CRITICAL" if accepted_logins[ip] else "HIGH"
        title = f"SSH brute-force pattern from {ip}"
        description = (
            f"{ip} generated {failed_count} failed SSH login attempts. "
            "A successful login followed the failures." if accepted_logins[ip]
            else f"{ip} generated {failed_count} failed SSH login attempts."
        )
        findings.append(
            Finding(
                title=title,
                severity=severity,
                description=description,
                evidence={
                    "source_ip": ip,
                    "failed_attempts": failed_count,
                    "line_numbers": lines,
                    "top_targeted_users": dict(targeted_users[ip].most_common(5)),
                    "accepted_logins_from_ip": accepted_logins[ip],
                },
                recommendation=(
                    "Search for successful authentications from this source, block or rate-limit "
                    "the IP, enforce MFA, and disable password-based SSH where possible."
                ),
                mitre_attack=["T1110 Brute Force", "T1021.004 SSH"],
                source=str(log_file),
            )
        )

    return findings


def detect_failed_logins(log_file, threshold=3):
    findings = analyze_failed_logins(log_file, threshold)
    print("\nSecurity Finding: Failed Login Analysis")
    print("-" * 45)
    if not findings:
        print("No suspicious failed login activity detected.")
        return
    for finding in findings:
        print(f"[{finding.severity}] {finding.evidence['source_ip']}")
        print(f"      Failed login attempts: {finding.evidence['failed_attempts']}")
        print(f"      Targeted users: {finding.evidence['top_targeted_users']}")
        print(f"      MITRE ATT&CK: {', '.join(finding.mitre_attack)}\n")


def build_parser():
    parser = argparse.ArgumentParser(description="Detect SSH brute-force and suspicious login patterns.")
    parser.add_argument("log_file", type=existing_file, help="Authentication log to analyze.")
    parser.add_argument("--threshold", type=int, default=3, help="Failed login threshold per source IP.")
    add_common_output_args(parser)
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    results = analyze_failed_logins(args.log_file, args.threshold)
    emit_results(results, args, "log_anomaly_detector", "Security Finding: Failed Login Analysis")
