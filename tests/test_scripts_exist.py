from pathlib import Path
import json
import tempfile

from scripts.cloudtrail_analyzer import analyze_cloudtrail
from scripts.input_collector import collect_inputs
from scripts.incident_timeline import build_timeline
from scripts.iam_policy_checker import analyze_iam_policy
from scripts.ioc_checker import analyze_iocs
from scripts.log_anomaly_detector import analyze_failed_logins
from scripts.nmap_scan_parser import analyze_nmap_xml
from scripts.rule_scanner import analyze_rules
from scripts.risk_scoring import apply_risk_scores
from scripts.soar_playbooks import build_playbook_plan
from scripts.soc_triage import analyze_workspace
from scripts.threat_intel_enricher import enrich_findings
from scripts.windows_event_analyzer import analyze_windows_events


def test_security_scripts_exist():
    expected_scripts = [
        "scripts/log_anomaly_detector.py",
        "scripts/ioc_checker.py",
        "scripts/nmap_scan_parser.py",
        "scripts/iam_policy_checker.py",
        "scripts/soc_common.py",
        "scripts/soc_triage.py",
        "scripts/cloudtrail_analyzer.py",
        "scripts/windows_event_analyzer.py",
        "scripts/incident_timeline.py",
        "scripts/rule_scanner.py",
        "scripts/html_dashboard.py",
        "scripts/case_manager.py",
        "scripts/threat_intel_enricher.py",
        "scripts/risk_scoring.py",
        "scripts/soar_playbooks.py",
        "scripts/input_collector.py",
    ]

    for script in expected_scripts:
        assert Path(script).exists(), f"{script} does not exist"


def test_sample_data_exists():
    expected_files = [
        "sample-data/auth.log",
        "sample-data/iocs.txt",
        "sample-data/nmap_scan.xml",
        "sample-data/iam_policy.json",
        "sample-data/cloudtrail_events.json",
        "sample-data/windows_events.json",
        "sample-data/sigma_rules.yml",
        "sample-data/yara_rules.yar",
        "sample-data/threat_intel.json",
        "config/external_sources.example.json",
    ]

    for file_path in expected_files:
        assert Path(file_path).exists(), f"{file_path} does not exist"


def test_failed_login_analyzer_prioritizes_repeated_sources():
    findings = analyze_failed_logins("sample-data/auth.log", threshold=3)

    assert len(findings) == 2
    assert findings[0].severity == "HIGH"
    assert any(finding.evidence["source_ip"] == "45.33.21.10" for finding in findings)
    assert any("T1110" in finding.mitre_attack[0] for finding in findings)


def test_ioc_analyzer_returns_structured_matches():
    findings = analyze_iocs("sample-data/iocs.txt", "sample-data/auth.log")

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].evidence["ioc"] == "45.33.21.10"
    assert findings[0].evidence["type"] == "ip"


def test_nmap_analyzer_rates_open_services():
    findings = analyze_nmap_xml("sample-data/nmap_scan.xml")
    titles = {finding.title for finding in findings}

    assert len(findings) == 2
    assert "Open ssh service on 192.168.1.10:22" in titles
    assert "Open http service on 192.168.1.10:80" in titles
    assert any(finding.severity == "HIGH" for finding in findings)


def test_iam_analyzer_detects_wildcards_and_passrole():
    findings = analyze_iam_policy("sample-data/iam_policy.json")
    titles = {finding.title for finding in findings}

    assert "Risky IAM action allowed: *" in titles
    assert "Risky IAM action allowed: iam:PassRole" in titles
    assert any(finding.severity == "CRITICAL" for finding in findings)


def test_soc_triage_combines_all_analyzers():
    findings = analyze_workspace("sample-data", threshold=3)

    assert len(findings) >= 15
    assert findings[0].severity in {"CRITICAL", "HIGH"}
    assert findings[0].risk_score > 0


def test_cloudtrail_analyzer_detects_privilege_activity():
    findings = analyze_cloudtrail("sample-data/cloudtrail_events.json")
    titles = {finding.title for finding in findings}

    assert "Failed AWS root console login" in titles
    assert "High-risk CloudTrail event: AttachUserPolicy" in titles


def test_windows_event_analyzer_detects_ir_activity():
    findings = analyze_windows_events("sample-data/windows_events.json", threshold=2)
    titles = {finding.title for finding in findings}

    assert "Suspicious encoded PowerShell execution" in titles
    assert "User added to privileged group: Domain Admins" in titles
    assert any("Windows brute-force pattern" in title for title in titles)


def test_incident_timeline_combines_sources():
    timeline = build_timeline("sample-data")

    assert len(timeline) >= 10
    assert any(event["event_type"].startswith("aws_") for event in timeline)
    assert any(event["event_type"].startswith("windows_") for event in timeline)


def test_rule_scanner_matches_sigma_and_yara_rules():
    findings = analyze_rules(
        sigma_rules="sample-data/sigma_rules.yml",
        windows_events="sample-data/windows_events.json",
        yara_rules="sample-data/yara_rules.yar",
        target_file="sample-data/cloudtrail_events.json",
    )
    titles = {finding.title for finding in findings}

    assert "Sigma rule match: Suspicious Encoded PowerShell" in titles
    assert "YARA rule match: Suspicious_AdminAccess_Policy" in titles


def test_threat_intel_enrichment_adds_context():
    findings = analyze_workspace("sample-data", threshold=3, enrich=False, score=False)
    enriched = enrich_findings(findings, "sample-data/threat_intel.json")

    assert any(finding.enrichment.get("threat_intel_matches") for finding in enriched)


def test_risk_scoring_assigns_numeric_scores():
    findings = analyze_workspace("sample-data", threshold=3, enrich=True, score=False)
    scored = apply_risk_scores(findings)

    assert max(finding.risk_score for finding in scored) >= 90


def test_soar_playbooks_are_selected_from_findings():
    findings = analyze_workspace("sample-data", threshold=3)
    playbooks = build_playbook_plan(findings)

    assert "AWS Privilege Escalation Response" in playbooks
    assert "Windows Account Compromise Response" in playbooks


def test_input_collector_copies_normalized_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        source = tmp_path / "external_iocs.txt"
        config = tmp_path / "collector.json"
        output_dir = tmp_path / "collected"
        source.write_text("8.8.8.8\n", encoding="utf-8")
        config.write_text(
            json.dumps(
                {
                    "output_dir": str(output_dir),
                    "sources": [
                        {
                            "name": "test_iocs",
                            "type": "file",
                            "path": str(source),
                            "target": "iocs.txt",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        messages = collect_inputs(config)

        assert (output_dir / "iocs.txt").read_text(encoding="utf-8") == "8.8.8.8\n"
        assert "Copied" in messages[0]
