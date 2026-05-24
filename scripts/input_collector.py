import argparse
import json
import os
import shutil
from pathlib import Path
from urllib.request import Request, urlopen


ALLOWED_TARGETS = {
    "auth.log",
    "iocs.txt",
    "nmap_scan.xml",
    "iam_policy.json",
    "cloudtrail_events.json",
    "windows_events.json",
    "sigma_rules.yml",
    "yara_rules.yar",
    "threat_intel.json",
}


def load_config(config_path):
    return json.loads(Path(config_path).read_text(encoding="utf-8"))


def safe_target_path(output_dir, target_name):
    if target_name not in ALLOWED_TARGETS:
        raise ValueError(f"{target_name} is not a supported normalized target")
    return Path(output_dir) / target_name


def resolve_headers(headers_env):
    headers = {}
    for header_name, env_name in (headers_env or {}).items():
        value = os.getenv(env_name)
        if value:
            headers[header_name] = value
    return headers


def collect_file(source, output_dir, dry_run=False):
    source_path = Path(source["path"])
    target_path = safe_target_path(output_dir, source["target"])
    if dry_run:
        return f"Would copy {source_path} -> {target_path}"
    if not source_path.is_file():
        raise FileNotFoundError(f"{source_path} does not exist")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_path, target_path)
    return f"Copied {source_path} -> {target_path}"


def collect_url(source, output_dir, dry_run=False):
    target_path = safe_target_path(output_dir, source["target"])
    headers = resolve_headers(source.get("headers_env"))
    if dry_run:
        return f"Would fetch {source['url']} -> {target_path}"
    target_path.parent.mkdir(parents=True, exist_ok=True)
    request = Request(source["url"], headers=headers)
    with urlopen(request, timeout=30) as response:
        target_path.write_bytes(response.read())
    return f"Fetched {source['url']} -> {target_path}"


def collect_inputs(config_path, output_dir=None, dry_run=False):
    config = load_config(config_path)
    destination = output_dir or config.get("output_dir", "collected-data")
    messages = []

    for source in config.get("sources", []):
        source_type = source.get("type")
        if source_type == "file":
            messages.append(collect_file(source, destination, dry_run=dry_run))
        elif source_type == "url":
            messages.append(collect_url(source, destination, dry_run=dry_run))
        else:
            raise ValueError(f"Unsupported source type: {source_type}")

    return messages


def build_parser():
    parser = argparse.ArgumentParser(
        description="Collect externalized inputs into a normalized SOC toolkit data directory."
    )
    parser.add_argument("--config", required=True, help="Collector config JSON file.")
    parser.add_argument("--output-dir", help="Override output directory from config.")
    parser.add_argument("--dry-run", action="store_true", help="Show planned collection actions without writing files.")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    for message in collect_inputs(args.config, output_dir=args.output_dir, dry_run=args.dry_run):
        print(message)
