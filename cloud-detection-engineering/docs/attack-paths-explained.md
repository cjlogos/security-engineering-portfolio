# Attack Paths Explained — MITRE ATT&CK Cloud Mapping

This document maps each detection rule to the corresponding MITRE ATT&CK techniques and provides detailed multi-step attack chain narratives for AWS cloud environments. This mapping provides a shared language for communicating risks to security teams, SOC analysts, and leadership.

---

## Detection Rule → ATT&CK Mapping

| Rule ID | Detection Rule | MITRE Technique | Technique ID | Tactic |
|---------|---------------|-----------------|--------------|--------|
| CDE-001 | IAM Key Created for Another User | Account Manipulation: Additional Cloud Credentials | T1098.001 | Persistence |
| CDE-002 | S3 Bucket Policy Changed to Public | Data from Cloud Storage Object | T1530 | Collection |
| CDE-003 | Admin Policy Attached to User | Account Manipulation | T1098 | Privilege Escalation |
| CDE-004 | Console Login Without MFA | Valid Accounts | T1078 | Initial Access |
| CDE-005 | CloudTrail Logging Tampering | Impair Defenses: Disable Cloud Logs | T1562.008 | Defense Evasion |
| CDE-006 | Security Group Opened to 0.0.0.0/0 | Impair Defenses | T1562 | Defense Evasion |
| CDE-007 | API Activity from Unusual Region | Valid Accounts | T1078 | Lateral Movement |
| CDE-008 | Root Account Usage | Valid Accounts: Cloud Accounts | T1078.004 | Privilege Escalation |

---

## Detailed Attack Path Narratives

### Path 1: Stolen IAM Keys → Privilege Escalation → Data Exfiltration

**ATT&CK Chain:** T1078 → T1098 → T1098.001 → T1530

```
Attacker finds AWS access keys in a public GitHub repository
  → Initial Access: Valid Accounts (T1078)
    → Keys belong to a developer with iam:AttachUserPolicy permission
  → Privilege Escalation: Account Manipulation (T1098)
    → Attacker attaches AdministratorAccess to their compromised user
    → CDE-003 FIRES: Admin policy attachment detected
  → Persistence: Additional Cloud Credentials (T1098.001)
    → Attacker creates new access keys on a different user for backup access
    → CDE-001 FIRES: Cross-user key creation detected
  → Collection: Data from Cloud Storage (T1530)
    → Attacker makes S3 bucket public and downloads customer data
    → CDE-002 FIRES: S3 bucket made public
```

**Detection Opportunities:** CDE-003 catches the privilege escalation, CDE-001 catches the persistence mechanism, and CDE-002 catches the data exfiltration preparation. Even if one detection is missed, the chain provides multiple chances to catch the attacker.

**Real-world prevalence:** Exposed AWS keys on GitHub are discovered by automated scanners within minutes. AWS reports that key exposure is one of the top 3 causes of cloud account compromise.

---

### Path 2: Phishing → Console Access → Defense Evasion → Undetected Operations

**ATT&CK Chain:** T1078 → T1562.008 → T1098 → T1078.004

```
Attacker phishes an admin user's AWS Console credentials
  → Initial Access: Valid Accounts (T1078)
    → Console login without MFA (password only)
    → CDE-004 FIRES: Console login without MFA detected
  → Defense Evasion: Disable Cloud Logs (T1562.008)
    → Attacker stops CloudTrail logging to blind defenders
    → CDE-005 FIRES: CloudTrail tampering detected
    → (If CDE-005 is missed, all subsequent actions are invisible)
  → Privilege Escalation: Account Manipulation (T1098)
    → Attacker creates a new admin user for persistence
  → Privilege Escalation: Root Account (T1078.004)
    → Attacker attempts to access the root account
    → CDE-008 FIRES: Root account usage detected
```

**Detection Opportunities:** The critical window is between CDE-004 (initial access) and CDE-005 (logging disabled). If CloudTrail is stopped before other detections fire, you lose visibility. This is why CDE-005 is rated CRITICAL and should trigger an immediate automated response (re-enable logging).

**Key takeaway:** The response time to CDE-005 determines whether the rest of the attack chain is visible or invisible. Automating the response to re-enable CloudTrail within seconds is the most impactful investment.

---

### Path 3: Compromised Service Role → Crypto Mining via Unusual Regions

**ATT&CK Chain:** T1078 → T1078 (lateral) → T1496

```
Attacker compromises an EC2 instance via SSRF and steals the instance role credentials
  → Initial Access: Instance metadata → temporary credentials
    → Attacker uses credentials from IMDSv1 (if not enforcing IMDSv2)
  → Lateral Movement: Valid Accounts in Other Regions (T1078)
    → Attacker launches GPU instances in eu-west-1, ap-northeast-1, us-west-2
    → CDE-007 FIRES: API activity in unusual regions detected
  → Impact: Resource Hijacking (T1496)
    → Crypto mining generates $10,000+ in charges per day across regions
    → AWS bill spike triggers after-the-fact detection (too late)
```

**Detection Opportunities:** CDE-007 is the early warning system. Detecting API calls in unexpected regions BEFORE the instances start mining can save thousands in charges. The alternative — waiting for the AWS bill — means days of undetected activity.

**Prevention note:** Enforcing IMDSv2 (which this project's Terraform config does via `http_tokens = "required"`) blocks the initial SSRF credential theft, preventing this entire chain.

---

### Path 4: Insider Threat → Network Exposure → External Access

**ATT&CK Chain:** T1562 → T1078 → T1530

```
Malicious insider with EC2 admin permissions
  → Defense Evasion: Modify Security Group (T1562)
    → Opens security group to allow SSH from their home IP (or 0.0.0.0/0)
    → CDE-006 FIRES: Security group opened to world
  → Lateral Movement: Direct instance access
    → Insider SSHs to EC2 instance from external network
    → Installs tools, pivots to internal resources
  → Collection: Data Access (T1530)
    → Insider accesses S3 data via the EC2 instance's IAM role
    → Data exfiltrated through the opened security group
```

**Detection Opportunities:** CDE-006 catches the network exposure. VPC Flow Logs (consumed by the ELK stack) can detect the external SSH connection. The combination of security group change + external connection + S3 data access creates a high-confidence alert chain.

---

### Path 5: AdminSDHolder Cloud Equivalent — Backdoor via Policy Manipulation

**ATT&CK Chain:** T1098 → T1098.001 → T1562.008

```
Attacker with IAM write access establishes multi-layer persistence
  → Persistence: Account Manipulation (T1098)
    → Creates an inline policy on a dormant service account granting admin access
    → CDE-003 FIRES if managed policy is used, but inline policies require deeper analysis
  → Persistence: Additional Credentials (T1098.001)
    → Creates access keys on the backdoored service account
    → CDE-001 FIRES: Cross-user key creation detected
  → Defense Evasion: Log Tampering (T1562.008)
    → Modifies CloudTrail event selectors to exclude IAM events
    → CDE-005 FIRES: PutEventSelectors detected
  → Persistence achieved across three independent mechanisms
    → Even if one backdoor is found, the others remain active
```

**Detection Opportunities:** This multi-layer persistence is the cloud equivalent of AdminSDHolder abuse in Active Directory (documented in the companion AD Privilege Escalation Analyzer). The key insight is the same: a single persistence mechanism is easy to remediate, but layered persistence requires systematic hunting across all credential types, policies, and logging configurations.

---

## Cross-Project Attack Path Comparison

For teams securing hybrid environments (on-prem AD + AWS cloud), the table below maps analogous attack techniques across both domains:

| Attack Pattern | On-Prem AD (AD Privilege Analyzer) | AWS Cloud (This Project) |
|---------------|-----------------------------------|--------------------------|
| Privilege Escalation | Nested group → Domain Admins | AttachUserPolicy → AdministratorAccess |
| Credential Persistence | Kerberoasting / DCSync | IAM access key creation (CDE-001) |
| Defense Evasion | AdminSDHolder ACL modification | CloudTrail StopLogging (CDE-005) |
| Data Access | ACL abuse → file share access | S3 bucket policy → public (CDE-002) |
| Stale Account Abuse | Stale DA with old password | Root account without MFA (CDE-008) |
| Network Exposure | Firewall rule modification | Security group 0.0.0.0/0 (CDE-006) |
| Audit Tampering | Event log clearing | CloudTrail deletion (CDE-005) |

---

## References

- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [MITRE ATT&CK for AWS](https://attack.mitre.org/matrices/enterprise/cloud/aws/)
- [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1098.001 — Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)
- [T1530 — Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
- [T1562.008 — Disable Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)
- [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1078.004 — Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [Rhino Security Labs — AWS Privilege Escalation Methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
