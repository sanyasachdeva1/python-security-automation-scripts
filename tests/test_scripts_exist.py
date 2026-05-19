from pathlib import Path


def test_security_scripts_exist():
    expected_scripts = [
        "scripts/log_anomaly_detector.py",
        "scripts/ioc_checker.py",
        "scripts/nmap_scan_parser.py",
        "scripts/iam_policy_checker.py",
    ]

    for script in expected_scripts:
        assert Path(script).exists(), f"{script} does not exist"


def test_sample_data_exists():
    expected_files = [
        "sample-data/auth.log",
        "sample-data/iocs.txt",
        "sample-data/nmap_scan.xml",
        "sample-data/iam_policy.json",
    ]

    for file_path in expected_files:
        assert Path(file_path).exists(), f"{file_path} does not exist"
