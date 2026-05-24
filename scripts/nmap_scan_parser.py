import argparse
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    from soc_common import Finding, add_common_output_args, emit_results, existing_file
except ModuleNotFoundError:
    from scripts.soc_common import Finding, add_common_output_args, emit_results, existing_file


HIGH_RISK_PORTS = {
    "21": "FTP is commonly abused for credential theft and data staging.",
    "22": "SSH is exposed and should be restricted to trusted management networks.",
    "23": "Telnet transmits credentials in cleartext.",
    "3389": "RDP exposure is frequently targeted by brute-force and ransomware operators.",
    "5900": "VNC exposure can enable remote desktop compromise.",
}
MEDIUM_RISK_PORTS = {
    "80": "HTTP should redirect to HTTPS and expose only required applications.",
    "445": "SMB exposure should be limited to trusted internal networks.",
    "3306": "Database services should not be broadly reachable.",
    "5432": "Database services should not be broadly reachable.",
}


def service_version(service_element):
    if service_element is None:
        return "unknown"
    parts = [
        service_element.attrib.get("product"),
        service_element.attrib.get("version"),
        service_element.attrib.get("extrainfo"),
    ]
    return " ".join(part for part in parts if part) or service_element.attrib.get("name", "unknown")


def analyze_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    findings = []

    for host in root.findall("host"):
        address_element = host.find("address")
        address = address_element.attrib.get("addr", "unknown") if address_element is not None else "unknown"

        open_services = []
        for port in host.findall(".//port"):
            port_id = port.attrib.get("portid", "unknown")
            protocol = port.attrib.get("protocol", "unknown")
            state_element = port.find("state")
            service_element = port.find("service")
            state = state_element.attrib.get("state") if state_element is not None else "unknown"
            service = service_element.attrib.get("name", "unknown") if service_element is not None else "unknown"

            if state != "open":
                continue

            open_services.append(
                {
                    "protocol": protocol,
                    "port": port_id,
                    "service": service,
                    "version": service_version(service_element),
                }
            )

        for service in open_services:
            risk_reason = HIGH_RISK_PORTS.get(service["port"])
            severity = "HIGH"
            if not risk_reason:
                risk_reason = MEDIUM_RISK_PORTS.get(service["port"], "Open service increases exposed attack surface.")
                severity = "MEDIUM"

            findings.append(
                Finding(
                    title=f"Open {service['service']} service on {address}:{service['port']}",
                    severity=severity,
                    description=risk_reason,
                    evidence={
                        "host": address,
                        "protocol": service["protocol"],
                        "port": service["port"],
                        "service": service["service"],
                        "version": service["version"],
                    },
                    recommendation=(
                        "Validate business need, restrict exposure with firewall or security group rules, "
                        "and confirm patch level for the exposed service."
                    ),
                    mitre_attack=["T1046 Network Service Discovery"],
                    source=str(xml_file),
                )
            )

    return findings


def parse_nmap_xml(xml_file):
    findings = analyze_nmap_xml(xml_file)

    print("\nSecurity Finding: Open Services from Nmap Scan")
    print("-" * 50)

    if not findings:
        print("No open services detected.")
        return

    for finding in findings:
        print(f"[{finding.severity}] {finding.evidence['host']}")
        print(
            f"[OPEN] {finding.evidence['protocol']}/{finding.evidence['port']} - "
            f"{finding.evidence['service']}"
        )
        print(f"Risk: {finding.description}\n")


def build_parser():
    parser = argparse.ArgumentParser(description="Parse Nmap XML and rate exposed services.")
    parser.add_argument("xml_file", type=existing_file, help="Nmap XML output file.")
    add_common_output_args(parser)
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    results = analyze_nmap_xml(args.xml_file)
    emit_results(results, args, "nmap_scan_parser", "Security Finding: Open Services from Nmap Scan")
