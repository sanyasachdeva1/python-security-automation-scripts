import argparse
import json
import re
from pathlib import Path

try:
    from soc_common import add_common_output_args, emit_results, existing_file
except ModuleNotFoundError:
    from scripts.soc_common import add_common_output_args, emit_results, existing_file


INDICATOR_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def load_threat_intel(intel_file):
    data = json.loads(Path(intel_file).read_text(encoding="utf-8"))
    return data.get("indicators", data)


def extract_indicators(finding):
    values = []

    def collect(value):
        if isinstance(value, dict):
            for nested in value.values():
                collect(nested)
        elif isinstance(value, list):
            for nested in value:
                collect(nested)
        else:
            values.extend(INDICATOR_PATTERN.findall(str(value)))

    collect(finding.evidence)
    collect(finding.description)
    collect(finding.title)
    return sorted(set(values))


def enrich_findings(findings, intel_file):
    intel = load_threat_intel(intel_file)
    for finding in findings:
        matches = {}
        for indicator in extract_indicators(finding):
            if indicator in intel:
                matches[indicator] = intel[indicator]
        if matches:
            finding.enrichment["threat_intel_matches"] = matches
            finding.enrichment["max_intel_confidence"] = max(item.get("confidence", 0) for item in matches.values())
            finding.enrichment["intel_sources"] = sorted({item.get("source", "unknown") for item in matches.values()})
    return findings


def build_parser():
    parser = argparse.ArgumentParser(description="Enrich SOC findings with local threat intelligence.")
    parser.add_argument("--data-dir", default="sample-data", help="Directory containing sample telemetry.")
    parser.add_argument("--intel-file", type=existing_file, default="sample-data/threat_intel.json")
    add_common_output_args(parser)
    return parser


if __name__ == "__main__":
    try:
        from soc_triage import analyze_workspace
    except ModuleNotFoundError:
        from scripts.soc_triage import analyze_workspace

    args = build_parser().parse_args()
    results = enrich_findings(analyze_workspace(args.data_dir, enrich=False, score=False), args.intel_file)
    emit_results(results, args, "threat_intel_enricher", "Threat Intel Enriched Findings")
