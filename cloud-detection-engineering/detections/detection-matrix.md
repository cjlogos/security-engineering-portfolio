# Detection Rule Matrix — MITRE ATT&CK Mapping

This matrix maps each detection rule in the Cloud Detection Engineering project to the corresponding MITRE ATT&CK techniques, providing a shared language for communicating detection coverage to security teams, SOC analysts, and leadership.

---

## Detection Rules → ATT&CK Mapping

| Rule ID | Detection Rule | MITRE Technique | Technique ID | Tactic | CloudTrail Event | Severity |
|---------|---------------|-----------------|--------------|--------|-----------------|----------|
| CDE-001 | IAM Key Created for Another User | Account Manipulation: Additional Cloud Credentials | T1098.001 | Persistence | CreateAccessKey | HIGH |
| CDE-002 | S3 Bucket Policy Changed to Public | Data from Cloud Storage Object | T1530 | Collection | PutBucketPolicy, PutBucketAcl | CRITICAL |
| CDE-003 | Admin Policy Attached to User | Account Manipulation | T1098 | Privilege Escalation | AttachUserPolicy, AttachRolePolicy | HIGH |
| CDE-004 | Console Login Without MFA | Valid Accounts | T1078 | Initial Access | ConsoleLogin | MEDIUM |
| CDE-005 | CloudTrail Logging Tampering | Impair Defenses: Disable Cloud Logs | T1562.008 | Defense Evasion | StopLogging, DeleteTrail, UpdateTrail | CRITICAL |
| CDE-006 | Security Group Opened to 0.0.0.0/0 | Impair Defenses | T1562 | Defense Evasion | AuthorizeSecurityGroupIngress | HIGH |
| CDE-007 | API Activity from Unusual Region | Valid Accounts | T1078 | Lateral Movement | Any (region filter) | MEDIUM |
| CDE-008 | Root Account Usage | Valid Accounts: Cloud Accounts | T1078.004 | Privilege Escalation | Any (root user filter) | CRITICAL |

---

## Coverage by MITRE Tactic

| Tactic | Detection Rules | Coverage |
|--------|----------------|----------|
| Initial Access | CDE-004 | Console login monitoring |
| Persistence | CDE-001 | Credential creation tracking |
| Privilege Escalation | CDE-003, CDE-008 | Policy attachment + root usage |
| Defense Evasion | CDE-005, CDE-006 | Logging tampering + network exposure |
| Lateral Movement | CDE-007 | Geographic anomaly detection |
| Collection | CDE-002 | Data exposure via S3 |

---

## Coverage by Severity

| Severity | Count | Rules |
|----------|-------|-------|
| CRITICAL | 3 | CDE-002 (S3 public), CDE-005 (CloudTrail tamper), CDE-008 (root usage) |
| HIGH | 3 | CDE-001 (IAM key), CDE-003 (priv esc), CDE-006 (SG opened) |
| MEDIUM | 2 | CDE-004 (no MFA login), CDE-007 (unusual region) |

---

## Detection Rules by Data Source

All 8 detection rules consume **AWS CloudTrail** as their primary data source. CloudTrail records every API call made in the AWS account, including:

- **Who** made the call (userIdentity)
- **What** they did (eventName)
- **When** they did it (eventTime)
- **Where** they did it from (sourceIPAddress, awsRegion)
- **Whether** it succeeded (errorCode)
- **What** they changed (requestParameters, responseElements)

This project uses a single CloudTrail trail with management events enabled (free tier). Data events (S3 object-level logging) can be enabled for deeper visibility at additional cost.

---

## Attack Path Coverage

The 8 detection rules cover the following common AWS attack chains:

### Path 1: Stolen Credentials → Privilege Escalation → Persistence
```
Credential theft (phishing, leaked keys)
  → CDE-004: Console login without MFA detected
  → CDE-003: Attacker attaches admin policy to their user
  → CDE-001: Attacker creates new access key for persistence
  → CDE-007: Attacker operates from unusual region
```

### Path 2: Admin Compromise → Data Exfiltration
```
Admin account compromised
  → CDE-002: Attacker makes S3 bucket public for exfiltration
  → CDE-005: Attacker disables CloudTrail to cover tracks
  → CDE-008: Attacker uses root account for maximum access
```

### Path 3: Network Exposure → Lateral Movement
```
Attacker gains initial access
  → CDE-006: Opens security group to allow external access
  → CDE-007: Begins operating in additional regions
  → CDE-005: Attempts to disable logging before deeper attack
```

---

## References

- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [MITRE ATT&CK for AWS](https://attack.mitre.org/matrices/enterprise/cloud/aws/)
- [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1530 — Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
- [T1562.008 — Disable Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)
- [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1078.004 — Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
