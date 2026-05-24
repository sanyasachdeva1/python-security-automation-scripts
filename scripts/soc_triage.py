import argparse
import json
from pathlib import Path

try:
    from cloudtrail_analyzer import analyze_cloudtrail
    from iam_policy_checker import analyze_iam_policy
    from ioc_checker import analyze_iocs
    from log_anomaly_detector import analyze_failed_logins
    from nmap_scan_parser import analyze_nmap_xml
    from risk_scoring import apply_risk_scores
    from rule_scanner import analyze_rules
    from threat_intel_enricher import enrich_findings
    from windows_event_analyzer import analyze_windows_events
    from soc_common import (
        add_common_output_args,
        emit_results,
        findings_to_dict,
        sort_findings,
        write_json_report,
        write_markdown_report,
)
except ModuleNotFoundError:
    from scripts.cloudtrail_analyzer import analyze_cloudtrail
    from scripts.iam_policy_checker import analyze_iam_policy
    from scripts.ioc_checker import analyze_iocs
    from scripts.log_anomaly_detector import analyze_failed_logins
    from scripts.nmap_scan_parser import analyze_nmap_xml
    from scripts.risk_scoring import apply_risk_scores
    from scripts.rule_scanner import analyze_rules
    from scripts.threat_intel_enricher import enrich_findings
    from scripts.windows_event_analyzer import analyze_windows_events
    from scripts.soc_common import (
        add_common_output_args,
        emit_results,
        findings_to_dict,
        sort_findings,
        write_json_report,
        write_markdown_report,
    )


DEFAULT_DATA_DIR = Path("sample-data")


def analyze_workspace(data_dir=DEFAULT_DATA_DIR, threshold=3, enrich=True, score=True):
    data_dir = Path(data_dir)
    findings = []

    auth_log = data_dir / "auth.log"
    ioc_file = data_dir / "iocs.txt"
    nmap_xml = data_dir / "nmap_scan.xml"
    iam_policy = data_dir / "iam_policy.json"
    cloudtrail = data_dir / "cloudtrail_events.json"
    windows_events = data_dir / "windows_events.json"
    sigma_rules = data_dir / "sigma_rules.yml"
    yara_rules = data_dir / "yara_rules.yar"
    threat_intel = data_dir / "threat_intel.json"

    if auth_log.exists():
        findings.extend(analyze_failed_logins(auth_log, threshold=threshold))
    if ioc_file.exists() and auth_log.exists():
        findings.extend(analyze_iocs(ioc_file, auth_log))
    if nmap_xml.exists():
        findings.extend(analyze_nmap_xml(nmap_xml))
    if iam_policy.exists():
        findings.extend(analyze_iam_policy(iam_policy))
    if cloudtrail.exists():
        findings.extend(analyze_cloudtrail(cloudtrail))
    if windows_events.exists():
        findings.extend(analyze_windows_events(windows_events, threshold=threshold))
    if sigma_rules.exists() and windows_events.exists():
        findings.extend(analyze_rules(sigma_rules=sigma_rules, windows_events=windows_events))
    if yara_rules.exists() and cloudtrail.exists():
        findings.extend(analyze_rules(yara_rules=yara_rules, target_file=cloudtrail))

    if enrich and threat_intel.exists():
        findings = enrich_findings(findings, threat_intel)
    if score:
        findings = apply_risk_scores(findings)

    return sort_findings(findings)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Run a SOC-style triage across sample logs, IOCs, Nmap XML, and IAM policy data."
    )
    parser.add_argument(
        "--data-dir",
        default=DEFAULT_DATA_DIR,
        type=Path,
        help="Directory containing auth.log, iocs.txt, nmap_scan.xml, and iam_policy.json.",
    )
    parser.add_argument("--threshold", type=int, default=3, help="Failed SSH login threshold.")
    add_common_output_args(parser)
    return parser


def main():
    args = build_parser().parse_args()
    findings = analyze_workspace(args.data_dir, args.threshold)

    if args.output and args.format == "json":
        write_json_report(findings, args.output, "soc_triage")
        print(f"Wrote JSON report to {args.output}")
        return

    if args.output and args.format == "markdown":
        write_markdown_report(findings, args.output, "SOC Triage Report")
        print(f"Wrote Markdown report to {args.output}")
        return

    if args.format == "json":
        print(json.dumps(findings_to_dict(findings, "soc_triage"), indent=2))
        return

    emit_results(findings, args, "soc_triage", "SOC Triage Report")


if __name__ == "__main__":
    main()
