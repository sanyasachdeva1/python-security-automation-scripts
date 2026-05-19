import sys
import json


RISKY_ACTIONS = {
    "*": "Full administrative access",
    "iam:PassRole": "Can pass roles to AWS services, possible privilege escalation",
    "sts:AssumeRole": "Can assume another role, may lead to privilege escalation",
    "iam:CreateUser": "Can create new IAM users",
    "iam:AttachUserPolicy": "Can attach permissions to users"
}


def normalize_to_list(value):
    if isinstance(value, list):
        return value
    return [value]


def check_iam_policy(policy_file):
    with open(policy_file, "r") as file:
        policy = json.load(file)

    print("\nSecurity Finding: IAM Policy Risk Review")
    print("-" * 45)

    risky_findings = []
    statements = policy.get("Statement", [])

    for index, statement in enumerate(statements, start=1):
        effect = statement.get("Effect")
        actions = normalize_to_list(statement.get("Action", []))
        resources = normalize_to_list(statement.get("Resource", []))

        if effect != "Allow":
            continue

        for action in actions:
            if action in RISKY_ACTIONS:
                risky_findings.append({
                    "statement": index,
                    "permission": action,
                    "risk": RISKY_ACTIONS[action]
                })

        if "*" in resources:
            risky_findings.append({
                "statement": index,
                "permission": "Resource:*",
                "risk": "Permission applies to all resources"
            })

    if risky_findings:
        for finding in risky_findings:
            print(f"[HIGH] Statement {finding['statement']}")
            print(f"       Risky permission: {finding['permission']}")
            print(f"       Risk: {finding['risk']}\n")
    else:
        print("No high-risk IAM permissions detected.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/iam_policy_checker.py sample-data/iam_policy.json")
        sys.exit(1)

    check_iam_policy(sys.argv[1])
