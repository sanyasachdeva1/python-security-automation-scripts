import argparse
import json
from pathlib import Path

try:
    from soc_common import Finding, add_common_output_args, emit_results, existing_file
except ModuleNotFoundError:
    from scripts.soc_common import Finding, add_common_output_args, emit_results, existing_file


HIGH_RISK_EVENTS = {
    "CreateAccessKey": "Creation of long-lived AWS credentials can enable persistence.",
    "AttachUserPolicy": "Attaching policies can escalate account privileges.",
    "PutUserPolicy": "Inline user policies can hide privilege escalation.",
    "CreateLoginProfile": "Console login setup can enable interactive access.",
    "AssumeRole": "Role assumption should be reviewed for unusual source or target.",
    "PutBucketPolicy": "Bucket policy changes can expose sensitive data.",
    "AuthorizeSecurityGroupIngress": "Security group changes can expose services.",
}


def load_cloudtrail_records(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    return data.get("Records", [])


def principal_name(record):
    identity = record.get("userIdentity", {})
    return identity.get("userName") or identity.get("arn") or identity.get("type", "unknown")


def analyze_cloudtrail(cloudtrail_file):
    findings = []
    for index, record in enumerate(load_cloudtrail_records(cloudtrail_file), start=1):
        event_name = record.get("eventName", "unknown")
        source_ip = record.get("sourceIPAddress", "unknown")
        event_time = record.get("eventTime", "unknown")
        user = principal_name(record)

        if event_name == "ConsoleLogin":
            login_result = record.get("responseElements", {}).get("ConsoleLogin", "Unknown")
            mfa_used = record.get("additionalEventData", {}).get("MFAUsed", "Unknown")
            identity_type = record.get("userIdentity", {}).get("type", "unknown")
            if login_result == "Failure" and identity_type == "Root":
                findings.append(
                    Finding(
                        title="Failed AWS root console login",
                        severity="HIGH",
                        description="A failed root console login attempt was observed.",
                        evidence={
                            "record": index,
                            "event_time": event_time,
                            "source_ip": source_ip,
                            "principal": user,
                            "mfa_used": mfa_used,
                        },
                        recommendation="Confirm the source, enforce MFA, and monitor for additional root login attempts.",
                        mitre_attack=["T1078 Valid Accounts"],
                        source=str(cloudtrail_file),
                    )
                )
            continue

        if event_name in HIGH_RISK_EVENTS:
            severity = "CRITICAL" if event_name in {"AttachUserPolicy", "PutUserPolicy"} else "HIGH"
            findings.append(
                Finding(
                    title=f"High-risk CloudTrail event: {event_name}",
                    severity=severity,
                    description=HIGH_RISK_EVENTS[event_name],
                    evidence={
                        "record": index,
                        "event_time": event_time,
                        "source_ip": source_ip,
                        "principal": user,
                        "aws_region": record.get("awsRegion", "unknown"),
                        "request_parameters": record.get("requestParameters", {}),
                    },
                    recommendation=(
                        "Validate change ownership, review adjacent events for privilege escalation, "
                        "and revoke unauthorized access immediately."
                    ),
                    mitre_attack=["T1098 Account Manipulation", "T1078 Valid Accounts"],
                    source=str(cloudtrail_file),
                )
            )

    return findings


def build_parser():
    parser = argparse.ArgumentParser(description="Analyze AWS CloudTrail events for IR-relevant activity.")
    parser.add_argument("cloudtrail_file", type=existing_file, help="CloudTrail JSON file.")
    add_common_output_args(parser)
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    results = analyze_cloudtrail(args.cloudtrail_file)
    emit_results(results, args, "cloudtrail_analyzer", "CloudTrail Security Analysis")
