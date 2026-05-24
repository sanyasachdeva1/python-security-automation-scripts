import argparse
import json
from fnmatch import fnmatch
from pathlib import Path

try:
    from soc_common import Finding, add_common_output_args, emit_results, existing_file
except ModuleNotFoundError:
    from scripts.soc_common import Finding, add_common_output_args, emit_results, existing_file


RISKY_ACTIONS = {
    "*": "Full administrative access",
    "iam:*": "Full IAM administration can create privilege escalation paths",
    "ec2:*": "Full EC2 administration can expose data or alter network controls",
    "s3:*": "Full S3 administration can expose or destroy data",
    "iam:PassRole": "Can pass roles to AWS services, possible privilege escalation",
    "sts:AssumeRole": "Can assume another role, may lead to privilege escalation",
    "iam:CreateUser": "Can create new IAM users",
    "iam:AttachUserPolicy": "Can attach permissions to users",
    "iam:PutUserPolicy": "Can add inline permissions to users",
    "iam:CreateAccessKey": "Can create long-lived credentials",
    "lambda:UpdateFunctionCode": "Can alter serverless execution paths",
}
PRIVILEGE_ESCALATION_PATTERNS = [
    "iam:PassRole",
    "sts:AssumeRole",
    "iam:Attach*Policy",
    "iam:Put*Policy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "lambda:UpdateFunctionCode",
    "cloudformation:CreateStack",
]


def normalize_to_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def action_matches(action, pattern):
    return fnmatch(action.lower(), pattern.lower())


def find_action_risk(action):
    normalized_action = action.lower()
    for risky_action, reason in RISKY_ACTIONS.items():
        if normalized_action == risky_action.lower():
            return reason
    return ""


def has_privilege_escalation_shape(actions):
    return [
        action
        for action in actions
        if any(action_matches(action, pattern) for pattern in PRIVILEGE_ESCALATION_PATTERNS)
    ]


def analyze_iam_policy(policy_file):
    with Path(policy_file).open("r", encoding="utf-8") as file:
        policy = json.load(file)

    findings = []
    statements = normalize_to_list(policy.get("Statement", []))

    for index, statement in enumerate(statements, start=1):
        effect = statement.get("Effect")
        actions = normalize_to_list(statement.get("Action", []))
        not_actions = normalize_to_list(statement.get("NotAction", []))
        resources = normalize_to_list(statement.get("Resource", []))
        conditions = statement.get("Condition", {})

        if effect != "Allow":
            continue

        for action in actions:
            risk = find_action_risk(action)
            if risk:
                findings.append(
                    Finding(
                        title=f"Risky IAM action allowed: {action}",
                        severity="CRITICAL" if action in ("*", "iam:*") else "HIGH",
                        description=risk,
                        evidence={
                            "statement": index,
                            "permission": action,
                            "resources": resources,
                            "conditions_present": bool(conditions),
                        },
                        recommendation=(
                            "Replace broad permissions with least-privilege actions, scope resources to "
                            "specific ARNs, and require conditions such as MFA or source network controls."
                        ),
                        mitre_attack=["T1098 Account Manipulation", "T1548 Abuse Elevation Control Mechanism"],
                        source=str(policy_file),
                    )
                )

        if "*" in resources:
            severity = "HIGH" if actions == ["*"] else "MEDIUM"
            findings.append(
                Finding(
                    title="IAM statement applies to all resources",
                    severity=severity,
                    description="The permission is not scoped to specific resources.",
                    evidence={
                        "statement": index,
                        "actions": actions,
                        "resource": "*",
                        "conditions_present": bool(conditions),
                    },
                    recommendation="Scope Resource to specific ARNs whenever the AWS service supports it.",
                    mitre_attack=["T1098 Account Manipulation"],
                    source=str(policy_file),
                )
            )

        if not_actions:
            findings.append(
                Finding(
                    title="IAM policy uses NotAction with Allow",
                    severity="HIGH",
                    description="Allow with NotAction can unintentionally grant a very broad permission set.",
                    evidence={
                        "statement": index,
                        "not_action": not_actions,
                        "resources": resources,
                    },
                    recommendation="Replace NotAction Allow statements with explicit Action allow lists.",
                    mitre_attack=["T1098 Account Manipulation"],
                    source=str(policy_file),
                )
            )

        escalation_actions = has_privilege_escalation_shape(actions)
        if escalation_actions and "*" in resources and not conditions:
            findings.append(
                Finding(
                    title="Potential IAM privilege escalation path",
                    severity="HIGH",
                    description="Privilege-sensitive actions are allowed against all resources without conditions.",
                    evidence={
                        "statement": index,
                        "privilege_escalation_actions": escalation_actions,
                        "resource": "*",
                    },
                    recommendation=(
                        "Require approval conditions and tightly scope role, policy, user, and function targets."
                    ),
                    mitre_attack=["T1548 Abuse Elevation Control Mechanism"],
                    source=str(policy_file),
                )
            )

    return findings


def check_iam_policy(policy_file):
    risky_findings = analyze_iam_policy(policy_file)

    print("\nSecurity Finding: IAM Policy Risk Review")
    print("-" * 45)

    if risky_findings:
        for finding in risky_findings:
            print(f"[{finding.severity}] Statement {finding.evidence['statement']}")
            print(f"       Finding: {finding.title}")
            print(f"       Risk: {finding.description}\n")
    else:
        print("No high-risk IAM permissions detected.")


def build_parser():
    parser = argparse.ArgumentParser(description="Review AWS IAM policy JSON for risky permissions.")
    parser.add_argument("policy_file", type=existing_file, help="IAM policy JSON file.")
    add_common_output_args(parser)
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    results = analyze_iam_policy(args.policy_file)
    emit_results(results, args, "iam_policy_checker", "Security Finding: IAM Policy Risk Review")
