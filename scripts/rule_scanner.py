import argparse
import json
import re
from pathlib import Path

try:
    from soc_common import Finding, add_common_output_args, emit_results, existing_file
except ModuleNotFoundError:
    from scripts.soc_common import Finding, add_common_output_args, emit_results, existing_file


def parse_simple_sigma(rule_file):
    rules = []
    for document in Path(rule_file).read_text(encoding="utf-8").split("---"):
        rule = {"detection": {}, "tags": []}
        current_list = None
        for raw_line in document.splitlines():
            line = raw_line.rstrip()
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("- ") and current_list is not None:
                current_list.append(stripped[2:].strip())
                continue
            if ":" not in stripped:
                continue
            key, value = stripped.split(":", 1)
            value = value.strip().strip("\"'")
            if key in {"title", "id", "description", "severity", "logsource"}:
                rule[key] = value
                current_list = None
            elif key == "tags":
                rule["tags"] = []
                current_list = rule["tags"]
            elif key == "detection":
                current_list = None
            else:
                if value:
                    rule["detection"][key] = value
                    current_list = None
                else:
                    rule["detection"][key] = []
                    current_list = rule["detection"][key]
        if rule.get("title"):
            rules.append(rule)
    return rules


def event_matches_sigma(event, rule):
    for key, expected in rule.get("detection", {}).items():
        contains = key.endswith("|contains")
        field = key.split("|", 1)[0]
        actual = str(event.get(field, ""))
        values = expected if isinstance(expected, list) else [expected]
        if contains:
            if not any(value.lower() in actual.lower() for value in values):
                return False
        elif str(event.get(field)) not in {str(value) for value in values}:
            return False
    return True


def scan_sigma(rule_file, event_file):
    rules = parse_simple_sigma(rule_file)
    events = json.loads(Path(event_file).read_text(encoding="utf-8"))
    findings = []
    for rule in rules:
        for index, event in enumerate(events, start=1):
            if event_matches_sigma(event, rule):
                findings.append(
                    Finding(
                        title=f"Sigma rule match: {rule['title']}",
                        severity=rule.get("severity", "medium").upper(),
                        description=rule.get("description", "Sigma rule matched an event."),
                        evidence={"rule_id": rule.get("id"), "record": index, "event": event},
                        recommendation="Triage the matching event and collect surrounding host telemetry.",
                        mitre_attack=rule.get("tags", []),
                        source=str(event_file),
                    )
                )
    return findings


def parse_yara_rules(rule_file):
    text = Path(rule_file).read_text(encoding="utf-8")
    parsed = []
    for match in re.finditer(r"rule\s+(\w+)\s*\{(.*?)\n\}", text, flags=re.DOTALL):
        name, body = match.groups()
        strings = re.findall(r"\$\w+\s*=\s*\"([^\"]+)\"", body)
        severity = re.search(r"severity\s*=\s*\"([^\"]+)\"", body)
        description = re.search(r"description\s*=\s*\"([^\"]+)\"", body)
        mitre = re.search(r"mitre\s*=\s*\"([^\"]+)\"", body)
        parsed.append(
            {
                "name": name,
                "strings": strings,
                "severity": severity.group(1) if severity else "MEDIUM",
                "description": description.group(1) if description else "YARA-style rule matched content.",
                "mitre": mitre.group(1) if mitre else "",
            }
        )
    return parsed


def scan_yara(rule_file, target_file):
    content = Path(target_file).read_text(encoding="utf-8", errors="ignore")
    findings = []
    for rule in parse_yara_rules(rule_file):
        matched_strings = [value for value in rule["strings"] if value.lower() in content.lower()]
        if matched_strings:
            findings.append(
                Finding(
                    title=f"YARA rule match: {rule['name']}",
                    severity=rule["severity"],
                    description=rule["description"],
                    evidence={"matched_strings": matched_strings, "target_file": str(target_file)},
                    recommendation="Inspect matching content and determine whether containment or eradication is required.",
                    mitre_attack=[rule["mitre"]] if rule["mitre"] else [],
                    source=str(target_file),
                )
            )
    return findings


def build_parser():
    parser = argparse.ArgumentParser(description="Run simple Sigma or YARA-style detections against sample data.")
    parser.add_argument("--sigma-rules", type=existing_file, help="Sigma YAML rule file.")
    parser.add_argument("--windows-events", type=existing_file, help="Windows events JSON file.")
    parser.add_argument("--yara-rules", type=existing_file, help="YARA rule file.")
    parser.add_argument("--target-file", type=existing_file, help="Text target file for YARA-style matching.")
    add_common_output_args(parser)
    return parser


def analyze_rules(sigma_rules=None, windows_events=None, yara_rules=None, target_file=None):
    findings = []
    if sigma_rules and windows_events:
        findings.extend(scan_sigma(sigma_rules, windows_events))
    if yara_rules and target_file:
        findings.extend(scan_yara(yara_rules, target_file))
    return findings


if __name__ == "__main__":
    args = build_parser().parse_args()
    results = analyze_rules(args.sigma_rules, args.windows_events, args.yara_rules, args.target_file)
    emit_results(results, args, "rule_scanner", "Detection Rule Scan Results")
