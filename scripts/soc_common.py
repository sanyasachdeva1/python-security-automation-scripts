import argparse
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    evidence: dict = field(default_factory=dict)
    recommendation: str = ""
    mitre_attack: list[str] = field(default_factory=list)
    source: str = ""
    risk_score: int = 0
    enrichment: dict = field(default_factory=dict)

    def __post_init__(self):
        self.severity = self.severity.upper()


def sort_findings(findings):
    return sorted(
        findings,
        key=lambda finding: (finding.risk_score, SEVERITY_ORDER.get(finding.severity, -1), finding.title),
        reverse=True,
    )


def summarize_findings(findings):
    summary = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        summary[finding.severity] = summary.get(finding.severity, 0) + 1
    return summary


def findings_to_dict(findings, tool_name):
    sorted_results = sort_findings(findings)
    return {
        "tool": tool_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summarize_findings(sorted_results),
        "finding_count": len(sorted_results),
        "findings": [asdict(finding) for finding in sorted_results],
    }


def write_json_report(findings, output_path, tool_name):
    report = findings_to_dict(findings, tool_name)
    Path(output_path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def write_markdown_report(findings, output_path, title):
    sorted_results = sort_findings(findings)
    lines = [
        f"# {title}",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Executive Summary",
        "",
        f"Total findings: {len(sorted_results)}",
        "",
    ]

    summary = summarize_findings(sorted_results)
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"- {severity}: {summary.get(severity, 0)}")

    lines.extend(["", "## Findings", ""])
    if not sorted_results:
        lines.append("No findings detected.")
    else:
        for index, finding in enumerate(sorted_results, start=1):
            lines.extend(
                [
                    f"### {index}. [{finding.severity}] {finding.title}",
                    "",
                    finding.description,
                    "",
                ]
            )
            if finding.mitre_attack:
                lines.append(f"MITRE ATT&CK: {', '.join(finding.mitre_attack)}")
                lines.append("")
            if finding.evidence:
                lines.append("Evidence:")
                for key, value in finding.evidence.items():
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value)
                    lines.append(f"- {key}: {value}")
                lines.append("")
            if finding.enrichment:
                lines.append("Threat Intel Enrichment:")
                for key, value in finding.enrichment.items():
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value)
                    lines.append(f"- {key}: {value}")
                lines.append("")
            if finding.risk_score:
                lines.append(f"Risk Score: {finding.risk_score}/100")
                lines.append("")
            if finding.recommendation:
                lines.append(f"Recommendation: {finding.recommendation}")
                lines.append("")

    Path(output_path).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def print_findings(findings, title):
    sorted_results = sort_findings(findings)
    print(f"\n{title}")
    print("-" * max(len(title), 50))

    if not sorted_results:
        print("No findings detected.")
        return

    for finding in sorted_results:
        print(f"[{finding.severity}] {finding.title}")
        print(f"Description: {finding.description}")
        if finding.mitre_attack:
            print(f"MITRE ATT&CK: {', '.join(finding.mitre_attack)}")
        for key, value in finding.evidence.items():
            print(f"{key}: {value}")
        if finding.enrichment:
            print(f"Threat Intel: {finding.enrichment}")
        if finding.risk_score:
            print(f"Risk Score: {finding.risk_score}/100")
        if finding.recommendation:
            print(f"Recommendation: {finding.recommendation}")
        print()


def add_common_output_args(parser):
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output format.",
    )
    parser.add_argument("--output", help="Write json or markdown output to this file.")


def emit_results(findings, args, tool_name, title):
    if args.output and args.format == "json":
        write_json_report(findings, args.output, tool_name)
        print(f"Wrote JSON report to {args.output}")
    elif args.output and args.format == "markdown":
        write_markdown_report(findings, args.output, title)
        print(f"Wrote Markdown report to {args.output}")
    elif args.format == "json":
        print(json.dumps(findings_to_dict(findings, tool_name), indent=2))
    elif args.format == "markdown":
        lines = []
        sorted_results = sort_findings(findings)
        lines.append(f"# {title}")
        lines.append("")
        if not sorted_results:
            lines.append("No findings detected.")
        for finding in sorted_results:
            lines.append(f"## [{finding.severity}] {finding.title}")
            lines.append(finding.description)
            lines.append("")
        print("\n".join(lines).rstrip())
    else:
        print_findings(findings, title)


def existing_file(value):
    path = Path(value)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"{value} is not a file")
    return path
