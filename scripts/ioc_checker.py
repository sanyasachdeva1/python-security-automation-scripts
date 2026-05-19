import sys


def load_iocs(ioc_file):
    with open(ioc_file, "r") as file:
        return set(line.strip() for line in file if line.strip())


def check_iocs(ioc_file, log_file):
    iocs = load_iocs(ioc_file)

    print("\nSecurity Finding: IOC Match Results")
    print("-" * 45)

    matches_found = False

    with open(log_file, "r") as file:
        for line_number, line in enumerate(file, start=1):
            for ioc in iocs:
                if ioc in line:
                    matches_found = True
                    print(f"[HIGH] IOC matched: {ioc}")
                    print(f"       Line number: {line_number}")
                    print(f"       Log entry: {line.strip()}\n")

    if not matches_found:
        print("No IOC matches found.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 scripts/ioc_checker.py sample-data/iocs.txt sample-data/auth.log")
        sys.exit(1)

    check_iocs(sys.argv[1], sys.argv[2])
