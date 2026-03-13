# Cloud Detection Engineering — Methodology

## Purpose

This document explains the reasoning behind each detection rule in the Cloud Detection Engineering project. For every detection, it covers three things: **why** this configuration or activity is dangerous, **how** an attacker exploits it in practice, and **what** defenders should do about it. The goal is not just to alert on suspicious events but to demonstrate understanding of the full cloud attack chain from initial access through data exfiltration.

---

## 1. IAM Access Key Creation for Another User (CDE-001)

### What We Detect

Any `CreateAccessKey` API call where the requesting principal is different from the target user.

### Why This Matters

IAM access keys are long-lived credentials that provide programmatic access to AWS. Unlike console passwords, they don't require MFA and don't expire by default. When an attacker creates a key for another user, they're establishing a persistent backdoor that survives password resets, MFA changes, and session revocations on the original compromised account.

### Real-World Exploitation

1. Attacker compromises an admin account via phishing or leaked credentials.
2. Attacker creates a new access key for a service account or low-profile user.
3. The original compromised admin password gets rotated during incident response.
4. Attacker still has access via the new key they created on the other account.
5. Because the key belongs to a different user, it doesn't show up in investigations focused on the originally compromised identity.

This is one of the most common persistence techniques in real AWS breaches. It's simple, fast (single API call), and often overlooked during remediation.

### Remediation

- Implement SCP or IAM boundary policies that restrict who can create access keys.
- Alert on all cross-user key creation and require approval via a change management process.
- Audit all access keys quarterly. Delete keys older than 90 days.
- Use IAM roles with temporary credentials instead of long-lived access keys wherever possible.

---

## 2. S3 Bucket Policy Changed to Public Access (CDE-002)

### What We Detect

Any `PutBucketPolicy` or `PutBucketAcl` call, particularly those that introduce `Principal: "*"` (public access).

### Why This Matters

S3 bucket misconfigurations have caused some of the largest data breaches in cloud history. A single API call can expose an entire bucket's contents to the public internet. Unlike traditional data exfiltration that requires moving data out, making a bucket public allows the attacker (or anyone else) to download data at will.

### Real-World Exploitation

1. Attacker gains access to an account with `s3:PutBucketPolicy` permission.
2. Attacker identifies buckets containing sensitive data (customer records, credentials, backups).
3. Attacker applies a public-read policy to the bucket.
4. Attacker downloads the data from any external location without leaving traces in VPC Flow Logs (S3 is accessed via public endpoints).
5. Alternatively, an insider accidentally sets a bucket to public during development, exposing data without malicious intent.

### Remediation

- Enable S3 Block Public Access at the **account level** (not just per-bucket) as a guardrail.
- Deploy AWS Config rules to automatically detect and remediate public buckets.
- Implement SCPs that prevent disabling Block Public Access.
- Use S3 access logging to track who accesses bucket contents after exposure.
- Tag sensitive buckets and create separate, stricter policies for them.

---

## 3. Privilege Escalation via Policy Attachment (CDE-003)

### What We Detect

`AttachUserPolicy`, `AttachRolePolicy`, or `PutUserPolicy` calls where the policy being attached grants administrative or full access (AdministratorAccess, PowerUserAccess, IAMFullAccess).

### Why This Matters

In AWS, IAM policies define what actions a principal can perform. Attaching `AdministratorAccess` to any user or role gives them unrestricted access to every service and resource in the account. This is the cloud equivalent of adding someone to Domain Admins — one API call transforms a low-privilege user into a full account administrator.

### Real-World Exploitation

1. Attacker compromises a user with `iam:AttachUserPolicy` permission (a common over-permission).
2. Attacker attaches `AdministratorAccess` to their own user or a user they control.
3. With admin access, the attacker can: create new backdoor users, disable security controls, access all data, launch compute for crypto mining, and modify billing.
4. Many organizations don't monitor policy attachments, so this escalation goes undetected until the damage is done.

The Rhino Security Labs AWS privilege escalation research documents over 20 distinct privilege escalation paths in AWS, with direct policy attachment being the most straightforward.

### Remediation

- Restrict `iam:Attach*Policy` and `iam:Put*Policy` permissions to a minimal set of admin roles.
- Implement IAM permission boundaries on all users and roles.
- Use SCPs in AWS Organizations to prevent specific dangerous policy attachments.
- Require MFA for IAM write operations via IAM policy conditions.
- Deploy real-time alerting on any admin-level policy attachment.

---

## 4. Console Login Without MFA (CDE-004)

### What We Detect

`ConsoleLogin` events where `additionalEventData.MFAUsed` is `"No"` and the login succeeded.

### Why This Matters

MFA is the single most effective control against credential-based attacks. Without MFA, a stolen password alone grants full console access. AWS reports that MFA prevents over 99% of account compromise attempts. A console login without MFA in an environment that requires MFA indicates either a policy gap or a deliberate bypass.

### Real-World Exploitation

1. Attacker obtains a user's password via phishing, credential stuffing, or a breach database.
2. If MFA is not configured, the attacker logs directly into the AWS Console.
3. Console access provides a visual interface to explore the account, download data, and make changes.
4. Console sessions generate fewer CloudTrail events per action compared to scripted API attacks, making them harder to detect via volume-based analytics.

### Remediation

- Enforce MFA for all IAM users via an IAM policy condition: `aws:MultiFactorAuthPresent`.
- Use AWS Organizations SCPs to deny console access without MFA.
- Implement hardware security keys (FIDO2) for privileged accounts.
- Monitor for `ConsoleLogin` events and alert on any successful login without MFA.
- Require MFA device registration as part of the user onboarding process.

---

## 5. CloudTrail Logging Tampering (CDE-005)

### What We Detect

Any `StopLogging`, `DeleteTrail`, `UpdateTrail`, or `PutEventSelectors` API call, regardless of whether it succeeded or failed.

### Why This Matters

CloudTrail is the audit trail for everything that happens in an AWS account. If an attacker can disable CloudTrail, all subsequent actions become invisible — no detection rules can fire because there are no events to analyze. This is the cloud equivalent of disabling CCTV cameras before robbing a bank.

### Real-World Exploitation

1. Attacker gains elevated access through any of the paths above (policy attachment, stolen admin creds).
2. Attacker's first action is to stop CloudTrail logging.
3. Once logging is disabled, the attacker freely: exfiltrates data, creates backdoor accounts, launches compute for mining, modifies security controls.
4. When logging is eventually re-enabled (if it ever is), there's a gap in the audit trail that may never be fully reconstructed.

Critically, the `StopLogging` call itself IS recorded by CloudTrail (it's the last event before the blind spot). That's why this detection fires on the attempt regardless of outcome.

### Remediation

- Use SCPs to deny `cloudtrail:StopLogging` and `cloudtrail:DeleteTrail` for all principals except a break-glass role.
- Enable multi-region trails so stopping one trail doesn't create a complete blind spot.
- Configure CloudTrail log file integrity validation to detect tampering with historical logs.
- Send CloudTrail logs to a separate, write-once S3 bucket in a different account (log archive account pattern).
- Set up CloudWatch alarms on CloudTrail status changes as a backup detection method.

---

## 6. Security Group Opened to 0.0.0.0/0 (CDE-006)

### What We Detect

`AuthorizeSecurityGroupIngress` calls where the ingress CIDR is `0.0.0.0/0`, especially on non-web ports (anything other than 80 and 443).

### Why This Matters

Security groups are the primary network access control for EC2 instances. Opening a security group to `0.0.0.0/0` means any IP address on the internet can reach the associated instances on the specified port. For SSH (22) or RDP (3389), this exposes the instance to brute-force attacks from the entire internet. For database ports (3306, 5432, 1433), it exposes data directly.

### Real-World Exploitation

1. Attacker gains access and needs a way to directly reach EC2 instances from outside the VPC.
2. Attacker opens SSH to 0.0.0.0/0 on the security group.
3. Attacker SSHs directly to the instance using stolen key pairs or exploits.
4. Alternatively, a developer "temporarily" opens a port for testing and forgets to close it, creating a persistent exposure.

### Remediation

- Implement AWS Config rule `restricted-ssh` to auto-detect and remediate 0.0.0.0/0 SSH rules.
- Use AWS Systems Manager Session Manager for remote access instead of SSH (no open inbound ports needed).
- Implement SCPs that prevent creating 0.0.0.0/0 ingress rules.
- Require all security group changes to go through a change management process.
- Deploy VPC Flow Logs and monitor for connection attempts to recently-opened ports.

---

## 7. API Activity from Unusual Region (CDE-007)

### What We Detect

API calls where `awsRegion` is not in the organization's expected region list (default: us-east-1 only).

### Why This Matters

Most organizations operate in 1-3 AWS regions. Activity in unexpected regions is a strong indicator of credential theft — an attacker using stolen keys from their own location will generate events in whatever region their tools default to. It's also a common pattern in crypto-mining attacks, where attackers spin up GPU instances in every available region to maximize mining output.

### Real-World Exploitation

1. Attacker obtains AWS credentials from a code repository, phishing, or metadata service exploit.
2. Attacker operates from a region the organization doesn't use (e.g., ap-southeast-1 for a US-based company).
3. API calls from this region appear in CloudTrail with the unusual awsRegion value.
4. In crypto-mining scenarios, the attacker runs `RunInstances` for expensive GPU instances across multiple regions simultaneously, generating thousands of dollars in charges within hours.

### Remediation

- Implement SCPs that deny all actions in unused regions (the most effective control).
- Monitor for `RunInstances` events in any region outside your operating set.
- Set up AWS Budgets with alerts to catch unexpected charges from rogue region usage.
- Use IAM policy conditions to restrict API calls to specific regions.
- Baseline your region usage over 30 days before implementing detections to avoid false positives.

---

## 8. Root Account Usage (CDE-008)

### What We Detect

Any CloudTrail event where `userIdentity.type` is `"Root"`, excluding service-linked role creation (which is an internal AWS action).

### Why This Matters

The root account is the God Mode of AWS. It cannot be restricted by IAM policies, SCPs, or permission boundaries. It can close the account, change the email address, modify the support plan, and access every resource regardless of any access controls in place. AWS has consistently recommended that organizations lock away root credentials and never use them for daily operations.

### Real-World Exploitation

1. Attacker obtains root account credentials (email + password, potentially through password reset attacks against the root email).
2. If MFA is not configured on root (a critical failure), the attacker has immediate full access.
3. Even with MFA, if the attacker compromises the root email account, they can reset the root password and MFA device.
4. With root access, the attacker can: create new admin users, disable all security controls, access all data, modify billing, and even close the AWS account.

Root account compromise is the worst-case scenario in AWS security. No detection or prevention control works against an actor with root access.

### Remediation

- Configure a strong, unique password and hardware MFA on the root account.
- Store root credentials in a physical safe or hardware security module.
- Never create access keys for the root account.
- Use AWS Organizations to centrally manage and monitor root account activity across all accounts.
- Enable root account activity alerts through CloudWatch Events / EventBridge.
- Implement a formal process for the rare scenarios that require root access.

---

## Testing Methodology

### Attack Simulation Framework

Each detection rule is validated by running a corresponding attack simulation script that generates the exact CloudTrail events the rule is designed to detect. The simulation framework:

1. Executes the attack using AWS CLI with lab IAM user profiles
2. Waits for CloudTrail to deliver events (5-15 minute delay)
3. Queries Elasticsearch for the expected events
4. Validates that the detection rule matches the attack events

### Automated Validation

The `tests/validate_detections.py` script runs each detection rule's Elasticsearch query and asserts that it returns results matching the simulated attacks. This is analogous to the 23-assertion test harness in the companion AD Privilege Escalation Analyzer project.

### Tuning Process

1. Run simulations to generate known-bad events
2. Validate detection rules catch all simulated attacks
3. Run the environment for 24-48 hours without simulations to baseline normal activity
4. Review any detection rule matches during the baseline period (these are false positives)
5. Add exclusions for legitimate patterns while documenting the rationale
6. Re-validate that detections still catch simulated attacks after tuning

---

## Limitations

- **CloudTrail delivery delay**: Events take 5-15 minutes to appear in S3. This means detection is near-real-time, not real-time. For real-time detection, consider CloudTrail → EventBridge → Lambda.
- **No network-level detection**: This project detects API-level attacks via CloudTrail. Network-level attacks (port scanning, exploitation) require VPC Flow Logs or a network IDS.
- **Single-account scope**: This lab covers one AWS account. Enterprise environments need multi-account detection via AWS Organizations + centralized logging.
- **No data event coverage by default**: S3 object-level reads (GetObject) are not logged unless data events are enabled (additional cost).
- **Management events only**: Lambda invocations, DynamoDB reads, and other data-plane events are not covered in the default configuration.
