# SOC Triage Report

Generated: 2026-05-24T08:11:48.234803+00:00

## Executive Summary

Total findings: 20

- CRITICAL: 4
- HIGH: 13
- MEDIUM: 3
- LOW: 0
- INFO: 0

## Findings

### 1. [CRITICAL] User added to privileged group: Domain Admins

A user was added to a privileged Windows group.

MITRE ATT&CK: T1098 Account Manipulation

Evidence:
- record: 6
- event_time: 2026-05-19T10:15:18Z
- host: WIN-DC01
- added_user: backup-admin
- group: Domain Admins
- actor: administrator

Risk Score: 100/100

Recommendation: Validate change ticket, remove unauthorized membership, and reset affected credentials.

### 2. [CRITICAL] Sigma rule match: Domain Admin Group Modification

Detects users added to Domain Admins.

MITRE ATT&CK: attack.t1098

Evidence:
- rule_id: demo-sigma-domain-admin-change
- record: 6
- event: {"TimeCreated": "2026-05-19T10:15:18Z", "EventID": 4732, "Computer": "WIN-DC01", "TargetUserName": "backup-admin", "GroupName": "Domain Admins", "SubjectUserName": "administrator"}

Risk Score: 100/100

Recommendation: Triage the matching event and collect surrounding host telemetry.

### 3. [CRITICAL] High-risk CloudTrail event: AttachUserPolicy

Attaching policies can escalate account privileges.

MITRE ATT&CK: T1098 Account Manipulation, T1078 Valid Accounts

Evidence:
- record: 3
- event_time: 2026-05-19T10:13:09Z
- source_ip: 103.25.44.8
- principal: analyst-temp
- aws_region: us-east-1
- request_parameters: {"userName": "backup-admin", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}

Threat Intel Enrichment:
- threat_intel_matches: {"103.25.44.8": {"type": "ip", "reputation": "suspicious", "confidence": 78, "source": "Local Threat Intel Feed", "tags": ["credential-access", "cloud-abuse"], "first_seen": "2026-05-12", "last_seen": "2026-05-19", "notes": "Associated with failed logons and suspicious AWS IAM activity."}}
- max_intel_confidence: 78
- intel_sources: ["Local Threat Intel Feed"]

Risk Score: 100/100

Recommendation: Validate change ownership, review adjacent events for privilege escalation, and revoke unauthorized access immediately.

### 4. [HIGH] YARA rule match: Suspicious_AdminAccess_Policy

AdministratorAccess policy reference

MITRE ATT&CK: T1098

Evidence:
- matched_strings: ["AdministratorAccess"]
- target_file: sample-data/cloudtrail_events.json

Risk Score: 88/100

Recommendation: Inspect matching content and determine whether containment or eradication is required.

### 5. [HIGH] Risky IAM action allowed: iam:PassRole

Can pass roles to AWS services, possible privilege escalation

MITRE ATT&CK: T1098 Account Manipulation, T1548 Abuse Elevation Control Mechanism

Evidence:
- statement: 2
- permission: iam:PassRole
- resources: ["*"]
- conditions_present: False

Risk Score: 86/100

Recommendation: Replace broad permissions with least-privilege actions, scope resources to specific ARNs, and require conditions such as MFA or source network controls.

### 6. [HIGH] Potential IAM privilege escalation path

Privilege-sensitive actions are allowed against all resources without conditions.

MITRE ATT&CK: T1548 Abuse Elevation Control Mechanism

Evidence:
- statement: 2
- privilege_escalation_actions: ["iam:PassRole"]
- resource: *

Risk Score: 86/100

Recommendation: Require approval conditions and tightly scope role, policy, user, and function targets.

### 7. [HIGH] Failed AWS root console login

A failed root console login attempt was observed.

MITRE ATT&CK: T1078 Valid Accounts

Evidence:
- record: 1
- event_time: 2026-05-19T10:08:14Z
- source_ip: 45.33.21.10
- principal: arn:aws:iam::123456789012:root
- mfa_used: No

Threat Intel Enrichment:
- threat_intel_matches: {"45.33.21.10": {"type": "ip", "reputation": "malicious", "confidence": 92, "source": "Local Threat Intel Feed", "tags": ["bruteforce", "scanner", "ssh"], "first_seen": "2026-05-01", "last_seen": "2026-05-19", "notes": "Observed in repeated SSH and Windows logon attempts."}}
- max_intel_confidence: 92
- intel_sources: ["Local Threat Intel Feed"]

Risk Score: 86/100

Recommendation: Confirm the source, enforce MFA, and monitor for additional root login attempts.

### 8. [HIGH] High-risk CloudTrail event: CreateAccessKey

Creation of long-lived AWS credentials can enable persistence.

MITRE ATT&CK: T1098 Account Manipulation, T1078 Valid Accounts

Evidence:
- record: 2
- event_time: 2026-05-19T10:11:42Z
- source_ip: 103.25.44.8
- principal: analyst-temp
- aws_region: us-east-1
- request_parameters: {"userName": "backup-admin"}

Threat Intel Enrichment:
- threat_intel_matches: {"103.25.44.8": {"type": "ip", "reputation": "suspicious", "confidence": 78, "source": "Local Threat Intel Feed", "tags": ["credential-access", "cloud-abuse"], "first_seen": "2026-05-12", "last_seen": "2026-05-19", "notes": "Associated with failed logons and suspicious AWS IAM activity."}}
- max_intel_confidence: 78
- intel_sources: ["Local Threat Intel Feed"]

Risk Score: 84/100

Recommendation: Validate change ownership, review adjacent events for privilege escalation, and revoke unauthorized access immediately.

### 9. [CRITICAL] Risky IAM action allowed: *

Full administrative access

MITRE ATT&CK: T1098 Account Manipulation, T1548 Abuse Elevation Control Mechanism

Evidence:
- statement: 1
- permission: *
- resources: ["*"]
- conditions_present: False

Risk Score: 80/100

Recommendation: Replace broad permissions with least-privilege actions, scope resources to specific ARNs, and require conditions such as MFA or source network controls.

### 10. [HIGH] SSH brute-force pattern from 103.25.44.8

103.25.44.8 generated 3 failed SSH login attempts.

MITRE ATT&CK: T1110 Brute Force, T1021.004 SSH

Evidence:
- source_ip: 103.25.44.8
- failed_attempts: 3
- line_numbers: [7, 8, 9]
- top_targeted_users: {"root": 3}
- accepted_logins_from_ip: 0

Threat Intel Enrichment:
- threat_intel_matches: {"103.25.44.8": {"type": "ip", "reputation": "suspicious", "confidence": 78, "source": "Local Threat Intel Feed", "tags": ["credential-access", "cloud-abuse"], "first_seen": "2026-05-12", "last_seen": "2026-05-19", "notes": "Associated with failed logons and suspicious AWS IAM activity."}}
- max_intel_confidence: 78
- intel_sources: ["Local Threat Intel Feed"]

Risk Score: 78/100

Recommendation: Search for successful authentications from this source, block or rate-limit the IP, enforce MFA, and disable password-based SSH where possible.

### 11. [HIGH] Suspicious encoded PowerShell execution

PowerShell was launched with encoded command arguments.

MITRE ATT&CK: T1059.001 PowerShell

Evidence:
- record: 4
- event_time: 2026-05-19T10:12:37Z
- host: WIN-WS01
- user: sanya
- process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- command_line: powershell.exe -NoP -EncodedCommand SQBFAFgA

Risk Score: 76/100

Recommendation: Collect process tree, script block logs, and endpoint telemetry for this host.

### 12. [HIGH] Sigma rule match: Suspicious Encoded PowerShell

Detects PowerShell launched with encoded command arguments.

MITRE ATT&CK: attack.t1059.001

Evidence:
- rule_id: demo-sigma-encoded-powershell
- record: 4
- event: {"TimeCreated": "2026-05-19T10:12:37Z", "EventID": 4688, "Computer": "WIN-WS01", "TargetUserName": "sanya", "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -NoP -EncodedCommand SQBFAFgA"}

Risk Score: 76/100

Recommendation: Triage the matching event and collect surrounding host telemetry.

### 13. [HIGH] SSH brute-force pattern from 45.33.21.10

45.33.21.10 generated 5 failed SSH login attempts.

MITRE ATT&CK: T1110 Brute Force, T1021.004 SSH

Evidence:
- source_ip: 45.33.21.10
- failed_attempts: 5
- line_numbers: [1, 2, 3, 4, 5]
- top_targeted_users: {"admin": 5}
- accepted_logins_from_ip: 0

Threat Intel Enrichment:
- threat_intel_matches: {"45.33.21.10": {"type": "ip", "reputation": "malicious", "confidence": 92, "source": "Local Threat Intel Feed", "tags": ["bruteforce", "scanner", "ssh"], "first_seen": "2026-05-01", "last_seen": "2026-05-19", "notes": "Observed in repeated SSH and Windows logon attempts."}}
- max_intel_confidence: 92
- intel_sources: ["Local Threat Intel Feed"]

Risk Score: 74/100

Recommendation: Search for successful authentications from this source, block or rate-limit the IP, enforce MFA, and disable password-based SSH where possible.

### 14. [HIGH] Known IOC observed: 45.33.21.10

A known ip indicator appeared 5 time(s) in the analyzed log.

MITRE ATT&CK: T1595 Active Scanning, T1071 Application Layer Protocol

Evidence:
- ioc: 45.33.21.10
- type: ip
- line_numbers: [1, 2, 3, 4, 5]
- sample_log: May 19 10:01:12 server sshd[101]: Failed password for admin from 45.33.21.10 port 55231 ssh2

Threat Intel Enrichment:
- threat_intel_matches: {"45.33.21.10": {"type": "ip", "reputation": "malicious", "confidence": 92, "source": "Local Threat Intel Feed", "tags": ["bruteforce", "scanner", "ssh"], "first_seen": "2026-05-01", "last_seen": "2026-05-19", "notes": "Observed in repeated SSH and Windows logon attempts."}}
- max_intel_confidence: 92
- intel_sources: ["Local Threat Intel Feed"]

Risk Score: 74/100

Recommendation: Pivot across SIEM, firewall, EDR, DNS, and authentication logs for this indicator, then contain affected assets if additional activity is confirmed.

### 15. [HIGH] High-risk CloudTrail event: PutBucketPolicy

Bucket policy changes can expose sensitive data.

MITRE ATT&CK: T1098 Account Manipulation, T1078 Valid Accounts

Evidence:
- record: 4
- event_time: 2026-05-19T10:18:22Z
- source_ip: 192.168.1.15
- principal: arn:aws:sts::123456789012:assumed-role/AppRole/session
- aws_region: us-east-1
- request_parameters: {"bucketName": "customer-backups"}

Risk Score: 66/100

Recommendation: Validate change ownership, review adjacent events for privilege escalation, and revoke unauthorized access immediately.

### 16. [HIGH] Open ssh service on 192.168.1.10:22

SSH is exposed and should be restricted to trusted management networks.

MITRE ATT&CK: T1046 Network Service Discovery

Evidence:
- host: 192.168.1.10
- protocol: tcp
- port: 22
- service: ssh
- version: ssh

Risk Score: 62/100

Recommendation: Validate business need, restrict exposure with firewall or security group rules, and confirm patch level for the exposed service.

### 17. [HIGH] IAM statement applies to all resources

The permission is not scoped to specific resources.

MITRE ATT&CK: T1098 Account Manipulation

Evidence:
- statement: 1
- actions: ["*"]
- resource: *
- conditions_present: False

Risk Score: 62/100

Recommendation: Scope Resource to specific ARNs whenever the AWS service supports it.

### 18. [MEDIUM] Windows account created: backup-admin

A new Windows account was created.

MITRE ATT&CK: T1136 Create Account

Evidence:
- record: 5
- event_time: 2026-05-19T10:14:52Z
- host: WIN-DC01
- created_user: backup-admin
- actor: administrator

Risk Score: 54/100

Recommendation: Confirm the account creation was authorized and review subsequent group changes.

### 19. [MEDIUM] IAM statement applies to all resources

The permission is not scoped to specific resources.

MITRE ATT&CK: T1098 Account Manipulation

Evidence:
- statement: 2
- actions: ["s3:GetObject", "iam:PassRole"]
- resource: *
- conditions_present: False

Risk Score: 54/100

Recommendation: Scope Resource to specific ARNs whenever the AWS service supports it.

### 20. [MEDIUM] Open http service on 192.168.1.10:80

HTTP should redirect to HTTPS and expose only required applications.

MITRE ATT&CK: T1046 Network Service Discovery

Evidence:
- host: 192.168.1.10
- protocol: tcp
- port: 80
- service: http
- version: http

Risk Score: 42/100

Recommendation: Validate business need, restrict exposure with firewall or security group rules, and confirm patch level for the exposed service.
