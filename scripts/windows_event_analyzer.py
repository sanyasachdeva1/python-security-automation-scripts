import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

try:
    from soc_common import Finding, add_common_output_args, emit_results, existing_file
except ModuleNotFoundError:
    from scripts.soc_common import Finding, add_common_output_args, emit_results, existing_file


FAILED_LOGON = 4625
SUCCESSFUL_LOGON = 4624
PROCESS_CREATE = 4688
USER_CREATED = 4720
GROUP_MEMBER_ADDED = 4732


def load_windows_events(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def analyze_windows_events(event_file, threshold=2):
    events = load_windows_events(event_file)
    findings = []
    failed_logons = defaultdict(list)
    successful_logons = Counter()

    for index, event in enumerate(events, start=1):
        event_id = int(event.get("EventID", 0))
        source_ip = event.get("IpAddress", "-")
        user = event.get("TargetUserName", "unknown")

        if event_id == FAILED_LOGON:
            failed_logons[source_ip].append((index, user, event.get("TimeCreated", "unknown")))
        elif event_id == SUCCESSFUL_LOGON:
            successful_logons[source_ip] += 1
        elif event_id == PROCESS_CREATE:
            command = event.get("CommandLine", "")
            process = event.get("NewProcessName", "")
            lowered = f"{process} {command}".lower()
            if "powershell" in lowered and ("encodedcommand" in lowered or " -enc" in lowered):
                findings.append(
                    Finding(
                        title="Suspicious encoded PowerShell execution",
                        severity="HIGH",
                        description="PowerShell was launched with encoded command arguments.",
                        evidence={
                            "record": index,
                            "event_time": event.get("TimeCreated", "unknown"),
                            "host": event.get("Computer", "unknown"),
                            "user": user,
                            "process": process,
                            "command_line": command,
                        },
                        recommendation="Collect process tree, script block logs, and endpoint telemetry for this host.",
                        mitre_attack=["T1059.001 PowerShell"],
                        source=str(event_file),
                    )
                )
        elif event_id == USER_CREATED:
            findings.append(
                Finding(
                    title=f"Windows account created: {user}",
                    severity="MEDIUM",
                    description="A new Windows account was created.",
                    evidence={
                        "record": index,
                        "event_time": event.get("TimeCreated", "unknown"),
                        "host": event.get("Computer", "unknown"),
                        "created_user": user,
                        "actor": event.get("SubjectUserName", "unknown"),
                    },
                    recommendation="Confirm the account creation was authorized and review subsequent group changes.",
                    mitre_attack=["T1136 Create Account"],
                    source=str(event_file),
                )
            )
        elif event_id == GROUP_MEMBER_ADDED:
            group_name = event.get("GroupName", "unknown")
            severity = "CRITICAL" if group_name.lower() == "domain admins" else "HIGH"
            findings.append(
                Finding(
                    title=f"User added to privileged group: {group_name}",
                    severity=severity,
                    description="A user was added to a privileged Windows group.",
                    evidence={
                        "record": index,
                        "event_time": event.get("TimeCreated", "unknown"),
                        "host": event.get("Computer", "unknown"),
                        "added_user": user,
                        "group": group_name,
                        "actor": event.get("SubjectUserName", "unknown"),
                    },
                    recommendation="Validate change ticket, remove unauthorized membership, and reset affected credentials.",
                    mitre_attack=["T1098 Account Manipulation"],
                    source=str(event_file),
                )
            )

    for source_ip, attempts in failed_logons.items():
        if source_ip == "-" or len(attempts) < threshold:
            continue
        severity = "CRITICAL" if successful_logons[source_ip] else "HIGH"
        findings.append(
            Finding(
                title=f"Windows brute-force pattern from {source_ip}",
                severity=severity,
                description=f"{source_ip} generated {len(attempts)} failed Windows logon events.",
                evidence={
                    "source_ip": source_ip,
                    "failed_logons": len(attempts),
                    "targeted_users": dict(Counter(user for _, user, _ in attempts)),
                    "event_records": [record for record, _, _ in attempts],
                    "successful_logons_from_ip": successful_logons[source_ip],
                },
                recommendation="Review RDP/VPN exposure, block the source, and inspect successful logons from the IP.",
                mitre_attack=["T1110 Brute Force", "T1021.001 Remote Desktop Protocol"],
                source=str(event_file),
            )
        )

    return findings


def build_parser():
    parser = argparse.ArgumentParser(description="Analyze Windows security events for SOC triage.")
    parser.add_argument("event_file", type=existing_file, help="Windows events JSON file.")
    parser.add_argument("--threshold", type=int, default=2, help="Failed logon threshold per source IP.")
    add_common_output_args(parser)
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    results = analyze_windows_events(args.event_file, args.threshold)
    emit_results(results, args, "windows_event_analyzer", "Windows Event Security Analysis")
