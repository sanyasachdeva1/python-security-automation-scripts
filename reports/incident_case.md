# Incident Case: IR-20260524081250

Created UTC: 2026-05-24T08:12:50.641497+00:00
Case Severity: Critical
Status: Open

## Executive Summary

The toolkit identified 20 findings across authentication logs, AWS CloudTrail, Windows events, IAM policy, exposure data, and detection rules.

## Severity Counts

- CRITICAL: 4
- HIGH: 13
- MEDIUM: 3
- LOW: 0
- INFO: 0

## Key Findings

- [CRITICAL] User added to privileged group: Domain Admins - risk 100/100 (sample-data/windows_events.json)
- [CRITICAL] Sigma rule match: Domain Admin Group Modification - risk 100/100 (sample-data/windows_events.json)
- [CRITICAL] High-risk CloudTrail event: AttachUserPolicy - risk 100/100 (sample-data/cloudtrail_events.json)
- [HIGH] YARA rule match: Suspicious_AdminAccess_Policy - risk 88/100 (sample-data/cloudtrail_events.json)
- [HIGH] Risky IAM action allowed: iam:PassRole - risk 86/100 (sample-data/iam_policy.json)
- [HIGH] Potential IAM privilege escalation path - risk 86/100 (sample-data/iam_policy.json)
- [HIGH] Failed AWS root console login - risk 86/100 (sample-data/cloudtrail_events.json)
- [HIGH] High-risk CloudTrail event: CreateAccessKey - risk 84/100 (sample-data/cloudtrail_events.json)
- [CRITICAL] Risky IAM action allowed: * - risk 80/100 (sample-data/iam_policy.json)
- [HIGH] SSH brute-force pattern from 103.25.44.8 - risk 78/100 (sample-data/auth.log)

## Timeline

- 2026-05-19T10:01:12Z `ssh_failed_login` sshd[101]: Failed password for admin from 45.33.21.10 port 55231 ssh2
- 2026-05-19T10:01:18Z `ssh_failed_login` sshd[102]: Failed password for admin from 45.33.21.10 port 55232 ssh2
- 2026-05-19T10:01:25Z `ssh_failed_login` sshd[103]: Failed password for admin from 45.33.21.10 port 55233 ssh2
- 2026-05-19T10:01:34Z `ssh_failed_login` sshd[104]: Failed password for admin from 45.33.21.10 port 55234 ssh2
- 2026-05-19T10:01:41Z `ssh_failed_login` sshd[105]: Failed password for admin from 45.33.21.10 port 55235 ssh2
- 2026-05-19T10:02:02Z `ssh_login` sshd[106]: Accepted password for sanya from 192.168.1.15 port 60122 ssh2
- 2026-05-19T10:05:10Z `ssh_failed_login` sshd[107]: Failed password for root from 103.25.44.8 port 33121 ssh2
- 2026-05-19T10:05:15Z `ssh_failed_login` sshd[108]: Failed password for root from 103.25.44.8 port 33122 ssh2
- 2026-05-19T10:05:20Z `ssh_failed_login` sshd[109]: Failed password for root from 103.25.44.8 port 33123 ssh2
- 2026-05-19T10:06:03Z `windows_4625` administrator
- 2026-05-19T10:06:11Z `windows_4625` administrator
- 2026-05-19T10:08:14Z `aws_ConsoleLogin` ConsoleLogin from 45.33.21.10
- 2026-05-19T10:09:44Z `windows_4624` administrator
- 2026-05-19T10:11:42Z `aws_CreateAccessKey` CreateAccessKey from 103.25.44.8
- 2026-05-19T10:12:37Z `windows_4688` powershell.exe -NoP -EncodedCommand SQBFAFgA
- 2026-05-19T10:13:09Z `aws_AttachUserPolicy` AttachUserPolicy from 103.25.44.8
- 2026-05-19T10:14:52Z `windows_4720` backup-admin
- 2026-05-19T10:15:18Z `windows_4732` Domain Admins
- 2026-05-19T10:18:22Z `aws_PutBucketPolicy` PutBucketPolicy from 192.168.1.15

## Recommended SOAR Playbooks

- Windows Account Compromise Response
- IOC Match Investigation
- AWS Privilege Escalation Response
- SSH Brute Force Response
- Exposed Service Review

## Response Checklist

- [ ] Validate whether suspicious activity is authorized.
- [ ] Preserve relevant logs and generated reports.
- [ ] Contain confirmed malicious source IPs or accounts.
- [ ] Rotate exposed credentials and remove unauthorized access.
- [ ] Document root cause, impact, and recovery actions.
- [ ] Close the case after validation and lessons learned.
