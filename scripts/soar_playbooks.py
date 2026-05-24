import argparse
from pathlib import Path

try:
    from soc_common import sort_findings
    from soc_triage import analyze_workspace
except ModuleNotFoundError:
    from scripts.soc_common import sort_findings
    from scripts.soc_triage import analyze_workspace


PLAYBOOKS = {
    "ssh_bruteforce": {
        "name": "SSH Brute Force Response",
        "match": ["ssh brute-force", "failed ssh"],
        "steps": [
            "Confirm source IP reputation and related authentication events.",
            "Search for successful logins from the same source IP.",
            "Block or rate-limit the source at firewall, WAF, or security group layer.",
            "Disable password-based SSH and enforce MFA where supported.",
            "Review affected account activity and rotate credentials if compromise is suspected.",
        ],
    },
    "aws_privilege_escalation": {
        "name": "AWS Privilege Escalation Response",
        "match": ["cloudtrail", "passrole", "attachuserpolicy", "createaccesskey", "administratoraccess"],
        "steps": [
            "Validate the CloudTrail event owner, source IP, and change window.",
            "Revoke unauthorized access keys, sessions, and policy attachments.",
            "Review IAM Access Analyzer and CloudTrail events before and after the alert.",
            "Scope permissions to least privilege and require MFA for sensitive actions.",
            "Document affected principals, resources, and blast radius.",
        ],
    },
    "windows_account_compromise": {
        "name": "Windows Account Compromise Response",
        "match": ["windows brute-force", "domain admins", "encoded powershell", "windows account"],
        "steps": [
            "Collect Windows Security, PowerShell, and Sysmon logs from the affected host.",
            "Validate account creation and privileged group membership changes.",
            "Isolate the host if malicious PowerShell execution is confirmed.",
            "Reset credentials for affected accounts and remove unauthorized group membership.",
            "Hunt for lateral movement and persistence across neighboring hosts.",
        ],
    },
    "ioc_match": {
        "name": "IOC Match Investigation",
        "match": ["ioc", "yara rule match", "sigma rule match"],
        "steps": [
            "Pivot on the indicator across SIEM, EDR, firewall, DNS, and proxy logs.",
            "Check threat-intel confidence, source, tags, first seen, and last seen.",
            "Identify affected assets and users that communicated with the indicator.",
            "Contain confirmed malicious indicators using blocklists or access controls.",
            "Record evidence and close as false positive only with clear justification.",
        ],
    },
    "exposed_service": {
        "name": "Exposed Service Review",
        "match": ["open ssh", "open http", "open service"],
        "steps": [
            "Confirm whether the exposed service has a valid business owner.",
            "Restrict management services to trusted networks or VPN.",
            "Verify patch level and service configuration hardening.",
            "Remove unused services and update firewall or security group rules.",
            "Schedule recurring exposure review for internet-facing assets.",
        ],
    },
}


def matched_playbooks(finding):
    text = f"{finding.title} {finding.description} {finding.source}".lower()
    matches = []
    for playbook in PLAYBOOKS.values():
        if any(token in text for token in playbook["match"]):
            matches.append(playbook)
    return matches


def build_playbook_plan(findings):
    plan = {}
    for finding in sort_findings(findings):
        for playbook in matched_playbooks(finding):
            entry = plan.setdefault(
                playbook["name"],
                {"steps": playbook["steps"], "findings": []},
            )
            entry["findings"].append(
                {
                    "title": finding.title,
                    "severity": finding.severity,
                    "risk_score": finding.risk_score,
                    "source": finding.source,
                }
            )
    return plan


def render_playbooks(findings):
    plan = build_playbook_plan(findings)
    lines = ["# SOAR Playbook Recommendations", ""]
    if not plan:
        lines.append("No matching playbooks were identified.")
        return "\n".join(lines) + "\n"

    for playbook_name, details in plan.items():
        lines.extend([f"## {playbook_name}", "", "Triggered By:", ""])
        for finding in details["findings"]:
            lines.append(
                f"- [{finding['severity']}] {finding['title']} "
                f"(risk {finding['risk_score']}/100, {finding['source']})"
            )
        lines.extend(["", "Response Steps:", ""])
        for index, step in enumerate(details["steps"], start=1):
            lines.append(f"{index}. {step}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def build_parser():
    parser = argparse.ArgumentParser(description="Generate SOAR-style playbook recommendations from findings.")
    parser.add_argument("--data-dir", default="sample-data", help="Directory containing sample telemetry.")
    parser.add_argument("--output", default="reports/soar_playbooks.md", help="Output Markdown path.")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_playbooks(analyze_workspace(args.data_dir)), encoding="utf-8")
    print(f"Wrote SOAR playbook recommendations to {output}")
