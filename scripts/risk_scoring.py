import argparse

try:
    from soc_common import SEVERITY_ORDER, add_common_output_args, emit_results
except ModuleNotFoundError:
    from scripts.soc_common import SEVERITY_ORDER, add_common_output_args, emit_results


SEVERITY_BASE_SCORE = {
    "CRITICAL": 80,
    "HIGH": 62,
    "MEDIUM": 42,
    "LOW": 22,
    "INFO": 5,
}


HIGH_IMPACT_KEYWORDS = {
    "root": 8,
    "administrator": 8,
    "domain admins": 16,
    "administratoraccess": 14,
    "passrole": 12,
    "createaccesskey": 10,
    "encoded powershell": 10,
    "privilege escalation": 12,
    "successful": 8,
}


def score_finding(finding):
    score = SEVERITY_BASE_SCORE.get(finding.severity, SEVERITY_ORDER.get(finding.severity, 0) * 10)
    text = " ".join(
        [
            finding.title,
            finding.description,
            str(finding.evidence),
            " ".join(finding.mitre_attack),
            str(finding.enrichment),
        ]
    ).lower()

    for keyword, weight in HIGH_IMPACT_KEYWORDS.items():
        if keyword in text:
            score += weight

    confidence = finding.enrichment.get("max_intel_confidence", 0)
    if confidence >= 90:
        score += 12
    elif confidence >= 70:
        score += 8
    elif confidence >= 50:
        score += 4

    if finding.evidence.get("accepted_logins_from_ip") or finding.evidence.get("successful_logons_from_ip"):
        score += 10

    if finding.source.endswith("cloudtrail_events.json") or finding.source.endswith("windows_events.json"):
        score += 4

    return min(score, 100)


def apply_risk_scores(findings):
    for finding in findings:
        finding.risk_score = score_finding(finding)
    return findings


def build_parser():
    parser = argparse.ArgumentParser(description="Apply numeric risk scoring to SOC findings.")
    parser.add_argument("--data-dir", default="sample-data", help="Directory containing sample telemetry.")
    add_common_output_args(parser)
    return parser


if __name__ == "__main__":
    try:
        from soc_triage import analyze_workspace
    except ModuleNotFoundError:
        from scripts.soc_triage import analyze_workspace

    args = build_parser().parse_args()
    results = analyze_workspace(args.data_dir, score=True)
    emit_results(results, args, "risk_scoring", "Risk Scored SOC Findings")
