import argparse
import json
import re
from pathlib import Path

try:
    from cloudtrail_analyzer import load_cloudtrail_records
    from windows_event_analyzer import load_windows_events
except ModuleNotFoundError:
    from scripts.cloudtrail_analyzer import load_cloudtrail_records
    from scripts.windows_event_analyzer import load_windows_events


AUTH_LOG_PATTERN = re.compile(r"^(?P<month>\w{3}) (?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<body>.*)$")
MONTHS = {
    "Jan": "01",
    "Feb": "02",
    "Mar": "03",
    "Apr": "04",
    "May": "05",
    "Jun": "06",
    "Jul": "07",
    "Aug": "08",
    "Sep": "09",
    "Oct": "10",
    "Nov": "11",
    "Dec": "12",
}


def auth_log_events(path):
    events = []
    if not Path(path).exists():
        return events
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        match = AUTH_LOG_PATTERN.match(line)
        if not match:
            continue
        body = match.group("body")
        event_type = "ssh_failed_login" if "Failed password" in body else "ssh_login" if "Accepted" in body else "auth_log"
        events.append(
            {
                "timestamp": f"2026-{MONTHS.get(match.group('month'), '01')}-{match.group('day').zfill(2)}T{match.group('time')}Z",
                "source": str(path),
                "event_type": event_type,
                "actor": "unknown",
                "asset": match.group("host"),
                "summary": body,
                "line": line_number,
            }
        )
    return events


def cloudtrail_events(path):
    if not Path(path).exists():
        return []
    events = []
    for index, record in enumerate(load_cloudtrail_records(path), start=1):
        identity = record.get("userIdentity", {})
        actor = identity.get("userName") or identity.get("arn") or identity.get("type", "unknown")
        events.append(
            {
                "timestamp": record.get("eventTime", "unknown"),
                "source": str(path),
                "event_type": f"aws_{record.get('eventName', 'unknown')}",
                "actor": actor,
                "asset": record.get("awsRegion", "unknown"),
                "summary": f"{record.get('eventName', 'unknown')} from {record.get('sourceIPAddress', 'unknown')}",
                "record": index,
            }
        )
    return events


def windows_events(path):
    if not Path(path).exists():
        return []
    events = []
    for index, event in enumerate(load_windows_events(path), start=1):
        events.append(
            {
                "timestamp": event.get("TimeCreated", "unknown"),
                "source": str(path),
                "event_type": f"windows_{event.get('EventID', 'unknown')}",
                "actor": event.get("SubjectUserName") or event.get("TargetUserName", "unknown"),
                "asset": event.get("Computer", "unknown"),
                "summary": event.get("CommandLine") or event.get("GroupName") or event.get("TargetUserName", "Windows event"),
                "record": index,
            }
        )
    return events


def build_timeline(data_dir):
    data_dir = Path(data_dir)
    events = []
    events.extend(auth_log_events(data_dir / "auth.log"))
    events.extend(cloudtrail_events(data_dir / "cloudtrail_events.json"))
    events.extend(windows_events(data_dir / "windows_events.json"))
    return sorted(events, key=lambda event: event["timestamp"])


def write_timeline_markdown(events, output_path):
    lines = ["# Incident Timeline", ""]
    for event in events:
        lines.append(
            f"- **{event['timestamp']}** `{event['event_type']}` "
            f"actor={event['actor']} asset={event['asset']} - {event['summary']}"
        )
    Path(output_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_parser():
    parser = argparse.ArgumentParser(description="Build an incident timeline across auth, CloudTrail, and Windows logs.")
    parser.add_argument("--data-dir", default="sample-data", help="Directory containing sample log files.")
    parser.add_argument("--output", help="Write Markdown timeline to this path.")
    parser.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    timeline = build_timeline(args.data_dir)
    if args.output:
        write_timeline_markdown(timeline, args.output)
        print(f"Wrote incident timeline to {args.output}")
    elif args.format == "json":
        print(json.dumps(timeline, indent=2))
    else:
        for item in timeline:
            print(f"{item['timestamp']} [{item['event_type']}] {item['summary']}")
