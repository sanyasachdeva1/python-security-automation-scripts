# SOAR Playbook Recommendations

## Windows Account Compromise Response

Triggered By:

- [CRITICAL] User added to privileged group: Domain Admins (risk 100/100, sample-data/windows_events.json)
- [CRITICAL] Sigma rule match: Domain Admin Group Modification (risk 100/100, sample-data/windows_events.json)
- [HIGH] Suspicious encoded PowerShell execution (risk 76/100, sample-data/windows_events.json)
- [HIGH] Sigma rule match: Suspicious Encoded PowerShell (risk 76/100, sample-data/windows_events.json)
- [MEDIUM] Windows account created: backup-admin (risk 54/100, sample-data/windows_events.json)

Response Steps:

1. Collect Windows Security, PowerShell, and Sysmon logs from the affected host.
2. Validate account creation and privileged group membership changes.
3. Isolate the host if malicious PowerShell execution is confirmed.
4. Reset credentials for affected accounts and remove unauthorized group membership.
5. Hunt for lateral movement and persistence across neighboring hosts.

## IOC Match Investigation

Triggered By:

- [CRITICAL] Sigma rule match: Domain Admin Group Modification (risk 100/100, sample-data/windows_events.json)
- [HIGH] YARA rule match: Suspicious_AdminAccess_Policy (risk 88/100, sample-data/cloudtrail_events.json)
- [HIGH] Sigma rule match: Suspicious Encoded PowerShell (risk 76/100, sample-data/windows_events.json)
- [HIGH] Known IOC observed: 45.33.21.10 (risk 74/100, sample-data/auth.log)

Response Steps:

1. Pivot on the indicator across SIEM, EDR, firewall, DNS, and proxy logs.
2. Check threat-intel confidence, source, tags, first seen, and last seen.
3. Identify affected assets and users that communicated with the indicator.
4. Contain confirmed malicious indicators using blocklists or access controls.
5. Record evidence and close as false positive only with clear justification.

## AWS Privilege Escalation Response

Triggered By:

- [CRITICAL] High-risk CloudTrail event: AttachUserPolicy (risk 100/100, sample-data/cloudtrail_events.json)
- [HIGH] YARA rule match: Suspicious_AdminAccess_Policy (risk 88/100, sample-data/cloudtrail_events.json)
- [HIGH] Risky IAM action allowed: iam:PassRole (risk 86/100, sample-data/iam_policy.json)
- [HIGH] Failed AWS root console login (risk 86/100, sample-data/cloudtrail_events.json)
- [HIGH] High-risk CloudTrail event: CreateAccessKey (risk 84/100, sample-data/cloudtrail_events.json)
- [HIGH] High-risk CloudTrail event: PutBucketPolicy (risk 66/100, sample-data/cloudtrail_events.json)

Response Steps:

1. Validate the CloudTrail event owner, source IP, and change window.
2. Revoke unauthorized access keys, sessions, and policy attachments.
3. Review IAM Access Analyzer and CloudTrail events before and after the alert.
4. Scope permissions to least privilege and require MFA for sensitive actions.
5. Document affected principals, resources, and blast radius.

## SSH Brute Force Response

Triggered By:

- [HIGH] SSH brute-force pattern from 103.25.44.8 (risk 78/100, sample-data/auth.log)
- [HIGH] SSH brute-force pattern from 45.33.21.10 (risk 74/100, sample-data/auth.log)

Response Steps:

1. Confirm source IP reputation and related authentication events.
2. Search for successful logins from the same source IP.
3. Block or rate-limit the source at firewall, WAF, or security group layer.
4. Disable password-based SSH and enforce MFA where supported.
5. Review affected account activity and rotate credentials if compromise is suspected.

## Exposed Service Review

Triggered By:

- [HIGH] Open ssh service on 192.168.1.10:22 (risk 62/100, sample-data/nmap_scan.xml)
- [MEDIUM] Open http service on 192.168.1.10:80 (risk 42/100, sample-data/nmap_scan.xml)

Response Steps:

1. Confirm whether the exposed service has a valid business owner.
2. Restrict management services to trusted networks or VPN.
3. Verify patch level and service configuration hardening.
4. Remove unused services and update firewall or security group rules.
5. Schedule recurring exposure review for internet-facing assets.
