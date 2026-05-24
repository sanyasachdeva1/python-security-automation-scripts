import argparse
from datetime import datetime, timezone
from pathlib import Path

try:
    from incident_timeline import build_timeline
    from soar_playbooks import build_playbook_plan
    from soc_common import sort_findings, summarize_findings
    from soc_triage import analyze_workspace
except ModuleNotFoundError:
    from scripts.incident_timeline import build_timeline
    from scripts.soar_playbooks import build_playbook_plan
    from scripts.soc_common import sort_findings, summarize_findings
    from scripts.soc_triage import analyze_workspace


def case_severity(summary):
    if summary.get("CRITICAL", 0):
        return "Critical"
    if summary.get("HIGH", 0):
        return "High"
    if summary.get("MEDIUM", 0):
        return "Medium"
    return "Low"


def render_case(data_dir):
    findings = sort_findings(analyze_workspace(data_dir))
    timeline = build_timeline(data_dir)
    playbooks = build_playbook_plan(findings)
    summary = summarize_findings(findings)
    severity = case_severity(summary)
    case_id = f"IR-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    lines = [
        f"# Incident Case: {case_id}",
        "",
        f"Created UTC: {datetime.now(timezone.utc).isoformat()}",
        f"Case Severity: {severity}",
        "Status: Open",
        "",
        "## Executive Summary",
        "",
        f"The toolkit identified {len(findings)} findings across authentication logs, AWS CloudTrail, Windows events, IAM policy, exposure data, and detection rules.",
        "",
        "## Severity Counts",
        "",
    ]
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"- {level}: {summary.get(level, 0)}")

    lines.extend(["", "## Key Findings", ""])
    for finding in findings[:10]:
        lines.append(f"- [{finding.severity}] {finding.title} - risk {finding.risk_score}/100 ({finding.source})")

    lines.extend(["", "## Timeline", ""])
    for event in timeline[:25]:
        lines.append(f"- {event['timestamp']} `{event['event_type']}` {event['summary']}")

    lines.extend(["", "## Recommended SOAR Playbooks", ""])
    for playbook_name in playbooks:
        lines.append(f"- {playbook_name}")

    lines.extend(
        [
            "",
            "## Response Checklist",
            "",
            "- [ ] Validate whether suspicious activity is authorized.",
            "- [ ] Preserve relevant logs and generated reports.",
            "- [ ] Contain confirmed malicious source IPs or accounts.",
            "- [ ] Rotate exposed credentials and remove unauthorized access.",
            "- [ ] Document root cause, impact, and recovery actions.",
            "- [ ] Close the case after validation and lessons learned.",
        ]
    )
    return "\n".join(lines) + "\n"


def build_parser():
    parser = argparse.ArgumentParser(description="Generate an incident case file from triage findings and timeline.")
    parser.add_argument("--data-dir", default="sample-data", help="Directory containing sample data.")
    parser.add_argument("--output", default="reports/incident_case.md", help="Output Markdown case path.")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_case(args.data_dir), encoding="utf-8")
    print(f"Wrote incident case file to {output}")
