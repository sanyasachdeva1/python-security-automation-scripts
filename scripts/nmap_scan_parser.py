import sys
import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    print("\nSecurity Finding: Open Services from Nmap Scan")
    print("-" * 50)

    for host in root.findall("host"):
        address = host.find("address").attrib.get("addr", "unknown")
        print(f"Host: {address}")

        for port in host.findall(".//port"):
            port_id = port.attrib.get("portid")
            protocol = port.attrib.get("protocol")

            state_element = port.find("state")
            service_element = port.find("service")

            state = state_element.attrib.get("state") if state_element is not None else "unknown"
            service = service_element.attrib.get("name") if service_element is not None else "unknown"

            if state == "open":
                print(f"[OPEN] {protocol}/{port_id} - {service}")

        print()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/nmap_scan_parser.py sample-data/nmap_scan.xml")
        sys.exit(1)

    parse_nmap_xml(sys.argv[1])
