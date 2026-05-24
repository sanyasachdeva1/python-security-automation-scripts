# Optional External Data Sources

The toolkit is offline-first by default. All current demos run from `sample-data/`.

For future production-like usage, external sources should be collected into a separate data directory with the same normalized filenames that the analyzers already understand.

## Normalized Input Contract

| Target filename | Expected content |
|---|---|
| `auth.log` | Linux authentication log text |
| `iocs.txt` | One IOC per line |
| `nmap_scan.xml` | Nmap XML output |
| `iam_policy.json` | AWS IAM policy JSON |
| `cloudtrail_events.json` | CloudTrail JSON with `Records` or a list of events |
| `windows_events.json` | JSON list of Windows event records |
| `sigma_rules.yml` | Simple Sigma-style YAML rules |
| `yara_rules.yar` | YARA-style text rules |
| `threat_intel.json` | Local threat intelligence JSON |

## Example Flow

Copy or fetch external data into `collected-data/`:

```bash
python3 scripts/input_collector.py \
  --config config/external_sources.example.json \
  --output-dir collected-data
```

Run triage against collected data:

```bash
python3 scripts/soc_triage.py --data-dir collected-data
```

Generate reports from collected data:

```bash
python3 scripts/soc_triage.py --data-dir collected-data --format markdown --output reports/external_triage_report.md
python3 scripts/case_manager.py --data-dir collected-data --output reports/external_incident_case.md
python3 scripts/html_dashboard.py --data-dir collected-data --output reports/external_dashboard.html
python3 scripts/soar_playbooks.py --data-dir collected-data --output reports/external_soar_playbooks.md
```

## Supported Collector Types

- `file`: copies an exported local file into the normalized data directory.
- `url`: fetches a URL into the normalized data directory. Optional headers can be supplied through environment variables.

## Secrets

Do not commit API keys, exported production logs, or real incident data.

Use environment variables for authorization headers:

```bash
export THREAT_INTEL_API_KEY="example-api-key"
export IOC_FEED_AUTH_HEADER="Bearer example-token"
```

The collector resolves `headers_env` values at runtime.

## Future Integrations

This design keeps live integrations optional. AWS, VirusTotal, AbuseIPDB, GreyNoise, OTX, SIEM exports, and EDR exports can all be added as collectors that write the same normalized files.
