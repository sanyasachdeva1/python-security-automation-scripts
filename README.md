# Python Security Automation Scripts

## Objective

This project contains Python scripts that automate common cybersecurity workflows used by SOC analysts, cloud security engineers, and incident response teams.

The goal is to reduce manual investigation time by parsing logs, detecting suspicious behavior, checking indicators of compromise, reviewing IAM policies, and generating simple security findings.

## Use Cases

- Detect repeated failed login attempts from authentication logs
- Check IP addresses, domains, or hashes against known IOC lists
- Parse Nmap scan results and summarize exposed services
- Review IAM policies for risky permissions
- Generate simple security reports from script outputs

## Tools & Skills Used

- Python
- Linux log analysis
- Nmap XML parsing
- IOC checking
- AWS IAM policy review
- Security automation
- Incident response fundamentals

## Project Status

This lab currently includes working Python scripts for:

- SSH failed-login detection
- IOC matching
- Nmap XML parsing
- IAM policy risk review

Each script includes sample input data and expected output for reproducibility.

## Security Concepts Demonstrated

- Brute-force detection
- Indicator of compromise matching
- Attack surface discovery
- Least-privilege IAM review
- First-level SOC triage automation

## Repository Structure

```text
scripts/       Python automation scripts
sample-data/   Sample logs, IOC files, Nmap XML, IAM policies
reports/       Example generated reports
screenshots/   Execution screenshots
docs/          Step-by-step lab documentation
