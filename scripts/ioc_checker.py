import argparse
import re
from pathlib import Path

try:
    from soc_common import Finding, add_common_output_args, emit_results, existing_file
except ModuleNotFoundError:
    from scripts.soc_common import Finding, add_common_output_args, emit_results, existing_file


IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{32,64}$")


def classify_ioc(ioc):
    if IP_PATTERN.match(ioc):
        return "ip"
    if HASH_PATTERN.match(ioc):
        return "hash"
    if "." in ioc:
        return "domain"
    return "keyword"


def load_iocs(ioc_file):
    with Path(ioc_file).open("r", encoding="utf-8") as file:
        return {
            line.strip()
            for line in file
            if line.strip() and not line.strip().startswith("#")
        }


def analyze_iocs(ioc_file, log_file):
    iocs = load_iocs(ioc_file)
    matches = {}

    with Path(log_file).open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            for ioc in iocs:
                if ioc in line:
                    entry = matches.setdefault(
                        ioc,
                        {
                            "ioc": ioc,
                            "type": classify_ioc(ioc),
                            "line_numbers": [],
                            "sample_log": line.strip(),
                        },
                    )
                    entry["line_numbers"].append(line_number)

    findings = []
    for match in matches.values():
        findings.append(
            Finding(
                title=f"Known IOC observed: {match['ioc']}",
                severity="HIGH",
                description=(
                    f"A known {match['type']} indicator appeared "
                    f"{len(match['line_numbers'])} time(s) in the analyzed log."
                ),
                evidence=match,
                recommendation=(
                    "Pivot across SIEM, firewall, EDR, DNS, and authentication logs for this "
                    "indicator, then contain affected assets if additional activity is confirmed."
                ),
                mitre_attack=["T1595 Active Scanning", "T1071 Application Layer Protocol"],
                source=str(log_file),
            )
        )

    return findings


def check_iocs(ioc_file, log_file):
    findings = analyze_iocs(ioc_file, log_file)

    print("\nSecurity Finding: IOC Match Results")
    print("-" * 45)

    if not findings:
        print("No IOC matches found.")
        return

    for finding in findings:
        print(f"[{finding.severity}] IOC matched: {finding.evidence['ioc']}")
        print(f"       Type: {finding.evidence['type']}")
        print(f"       Line numbers: {finding.evidence['line_numbers']}")
        print(f"       Sample log: {finding.evidence['sample_log']}\n")


def build_parser():
    parser = argparse.ArgumentParser(description="Match log contents against known indicators.")
    parser.add_argument("ioc_file", type=existing_file, help="Plain-text IOC list.")
    parser.add_argument("log_file", type=existing_file, help="Log file to search.")
    add_common_output_args(parser)
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    results = analyze_iocs(args.ioc_file, args.log_file)
    emit_results(results, args, "ioc_checker", "Security Finding: IOC Match Results")
