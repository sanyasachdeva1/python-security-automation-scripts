# Lab Steps

## Step 1: Clone the Repository

```bash
git clone https://github.com/sanyasachdeva1/python-security-automation-scripts.git
cd python-security-automation-scripts
```

## Step 2: Run the Individual Analyzers

```bash
python3 scripts/log_anomaly_detector.py sample-data/auth.log
python3 scripts/ioc_checker.py sample-data/iocs.txt sample-data/auth.log
python3 scripts/nmap_scan_parser.py sample-data/nmap_scan.xml
python3 scripts/iam_policy_checker.py sample-data/iam_policy.json
python3 scripts/cloudtrail_analyzer.py sample-data/cloudtrail_events.json
python3 scripts/windows_event_analyzer.py sample-data/windows_events.json
```

## Step 3: Run Full SOC Triage

```bash
python3 scripts/soc_triage.py
```

The triage runner combines authentication-log analysis, IOC matching, Nmap service review, and IAM policy review into a single prioritized finding list.

It also includes CloudTrail findings, Windows event findings, Sigma rule matches, and YARA-style content matches when the matching sample files are present.

## Step 4: Run Detection Rules

```bash
python3 scripts/rule_scanner.py \
  --sigma-rules sample-data/sigma_rules.yml \
  --windows-events sample-data/windows_events.json \
  --yara-rules sample-data/yara_rules.yar \
  --target-file sample-data/cloudtrail_events.json
```

## Step 5: Enrich and Score Findings

```bash
python3 scripts/threat_intel_enricher.py --intel-file sample-data/threat_intel.json --format json
python3 scripts/risk_scoring.py --format json
```

Threat intelligence is loaded from a local demo feed at `sample-data/threat_intel.json`. No external API keys or network calls are required.

## Step 6: Generate Reports

Generate a Markdown analyst report:

```bash
python3 scripts/soc_triage.py --format markdown --output reports/soc_triage_report.md
```

Generate machine-readable JSON for SIEM or SOAR-style handoff:

```bash
python3 scripts/soc_triage.py --format json --output reports/soc_triage_report.json
```

Generate the incident timeline, case file, and HTML dashboard:

```bash
python3 scripts/incident_timeline.py --output reports/incident_timeline.md
python3 scripts/case_manager.py --output reports/incident_case.md
python3 scripts/html_dashboard.py --output reports/soc_dashboard.html
python3 scripts/soar_playbooks.py --output reports/soar_playbooks.md
```

## Step 7: Validate the Project

```bash
python3 -m py_compile scripts/*.py
python3 -m pytest tests/
```

## Optional: Externalize Input Data

The default lab uses `sample-data/`. To test exported logs or future API feeds, collect them into a separate normalized directory:

```bash
python3 scripts/input_collector.py --config config/external_sources.example.json --dry-run
python3 scripts/input_collector.py --config config/external_sources.example.json --output-dir collected-data
python3 scripts/soc_triage.py --data-dir collected-data
```

Edit `config/external_sources.example.json` with your exported file paths or feed URLs before running the collector.

Do not commit real logs, secrets, API keys, or production incident data.

## Analyst Workflow

1. Review critical and high findings first.
2. Pivot on source IPs, matched IOCs, exposed services, and risky IAM actions.
3. Confirm whether any failed-login source also has accepted-login activity.
4. Review CloudTrail privilege events and Windows account or group changes.
5. Restrict exposed services and scope IAM resources to least privilege.
6. Use risk scores to prioritize the highest-impact response actions.
7. Use generated SOAR playbooks to structure containment and recovery.
8. Save Markdown, JSON, case, timeline, dashboard, and playbook output as investigation evidence.
