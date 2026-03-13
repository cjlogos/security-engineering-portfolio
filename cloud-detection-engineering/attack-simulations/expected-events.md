# Expected CloudTrail Events — Attack Simulation Reference

This document maps each attack simulation to the exact CloudTrail events it generates.
Use this as the blueprint for building and validating detection rules.

---

## Simulation 1: IAM Key Creation for Another User

| Field | Expected Value |
|-------|---------------|
| **eventName** | `CreateAccessKey` |
| **eventSource** | `iam.amazonaws.com` |
| **userIdentity.arn** | `arn:aws:iam::*:user/*lab-admin` |
| **requestParameters.userName** | `*lab-analyst` (different from the requester) |
| **MITRE Technique** | T1098.001 — Account Manipulation: Additional Cloud Credentials |
| **Detection Logic** | Alert when the user creating the key is different from the user the key is for |
| **Severity** | HIGH |

---

## Simulation 2: S3 Bucket Policy Change to Public

| Field | Expected Value |
|-------|---------------|
| **eventName** | `PutBucketPolicy` |
| **eventSource** | `s3.amazonaws.com` |
| **userIdentity.arn** | `arn:aws:iam::*:user/*lab-admin` |
| **requestParameters.bucketName** | `*misconfig*` |
| **requestParameters.bucketPolicy** | Contains `"Principal":"*"` |
| **MITRE Technique** | T1530 — Data from Cloud Storage |
| **Detection Logic** | Alert when a bucket policy contains `Principal: "*"` or `Principal: {"AWS": "*"}` |
| **Severity** | CRITICAL |

---

## Simulation 3: Privilege Escalation via Policy Attachment

| Field | Expected Value |
|-------|---------------|
| **eventName** | `AttachUserPolicy` |
| **eventSource** | `iam.amazonaws.com` |
| **userIdentity.arn** | `arn:aws:iam::*:user/*lab-admin` |
| **requestParameters.policyArn** | `arn:aws:iam::aws:policy/AdministratorAccess` |
| **requestParameters.userName** | `*lab-attacker` |
| **MITRE Technique** | T1098 — Account Manipulation |
| **Detection Logic** | Alert when AdministratorAccess or PowerUserAccess is attached to any user |
| **Severity** | HIGH |

---

## Simulation 4: CloudTrail Tampering — Stop Logging

| Field | Expected Value |
|-------|---------------|
| **eventName** | `StopLogging` |
| **eventSource** | `cloudtrail.amazonaws.com` |
| **userIdentity.arn** | `arn:aws:iam::*:user/*lab-attacker` |
| **requestParameters.name** | `*trail` |
| **errorCode** | `AccessDenied` (if attacker lacks permission) or empty (if succeeded) |
| **MITRE Technique** | T1562.008 — Impair Defenses: Disable Cloud Logs |
| **Detection Logic** | Alert on ANY StopLogging, DeleteTrail, UpdateTrail, or PutEventSelectors call |
| **Severity** | CRITICAL |

**Note:** Even failed attempts generate a CloudTrail event. The detection fires regardless of whether the action succeeded — the attempt itself is suspicious.

---

## Simulation 5: Security Group Opened to 0.0.0.0/0

| Field | Expected Value |
|-------|---------------|
| **eventName** | `AuthorizeSecurityGroupIngress` |
| **eventSource** | `ec2.amazonaws.com` |
| **userIdentity.arn** | `arn:aws:iam::*:user/*lab-admin` |
| **requestParameters.ipPermissions** | Contains `"cidrIp":"0.0.0.0/0"` |
| **MITRE Technique** | T1562 — Impair Defenses |
| **Detection Logic** | Alert when an ingress rule is added with `0.0.0.0/0` on non-80/443 ports |
| **Severity** | HIGH |

---

## Simulation 6: API Activity from Unusual Region

| Field | Expected Value |
|-------|---------------|
| **eventName** | `ListBuckets`, `DescribeInstances` |
| **eventSource** | `s3.amazonaws.com`, `ec2.amazonaws.com` |
| **awsRegion** | `eu-west-1`, `ap-southeast-1` (not `us-east-1`) |
| **userIdentity.arn** | `arn:aws:iam::*:user/*lab-admin` |
| **MITRE Technique** | T1078 — Valid Accounts |
| **Detection Logic** | Alert when API calls originate from regions not in the expected list (`us-east-1`) |
| **Severity** | MEDIUM |

---

## Simulation 7: IAM Reconnaissance — Account Enumeration

| Field | Expected Value |
|-------|---------------|
| **eventName** | `ListUsers`, `ListRoles`, `ListPolicies`, `GetAccountAuthorizationDetails` |
| **eventSource** | `iam.amazonaws.com` |
| **userIdentity.arn** | `arn:aws:iam::*:user/*lab-attacker` |
| **MITRE Technique** | T1087 — Account Discovery |
| **Detection Logic** | Alert when multiple IAM enumeration calls occur from the same user within a short window |
| **Severity** | MEDIUM |

---

## Simulation 8 (Manual): Console Login Without MFA

This is documented but not automated because it requires browser interaction.

| Field | Expected Value |
|-------|---------------|
| **eventName** | `ConsoleLogin` |
| **eventSource** | `signin.amazonaws.com` |
| **additionalEventData.MFAUsed** | `No` |
| **userIdentity.arn** | `arn:aws:iam::*:user/*lab-attacker` |
| **responseElements.ConsoleLogin** | `Success` or `Failure` |
| **MITRE Technique** | T1078 — Valid Accounts |
| **Detection Logic** | Alert when `ConsoleLogin` event has `MFAUsed: No` |
| **Severity** | MEDIUM |

**To simulate:** Create a console password for lab-attacker (`aws iam create-login-profile`), then log into the AWS Console at the IAM sign-in URL without setting up MFA.

---

## Simulation 9 (Manual): Root Account Usage

This is documented but not automated for safety.

| Field | Expected Value |
|-------|---------------|
| **eventName** | Any non-read-only event |
| **userIdentity.type** | `Root` |
| **MITRE Technique** | T1078.004 — Valid Accounts: Cloud Accounts |
| **Detection Logic** | Alert on any event where `userIdentity.type == "Root"` and `readOnly != true` |
| **Severity** | CRITICAL |

**To simulate:** Log into the AWS Console as the root user and perform any action (view a service page, change a setting). CloudTrail records this automatically.

---

## Quick Reference Matrix

| # | Simulation | eventName | MITRE ID | Severity | Automated |
|---|-----------|-----------|----------|----------|-----------|
| 1 | IAM Key for Other User | CreateAccessKey | T1098.001 | HIGH | Yes |
| 2 | S3 Bucket Made Public | PutBucketPolicy | T1530 | CRITICAL | Yes |
| 3 | Privilege Escalation | AttachUserPolicy | T1098 | HIGH | Yes |
| 4 | CloudTrail Tampering | StopLogging | T1562.008 | CRITICAL | Yes |
| 5 | Security Group Opened | AuthorizeSecurityGroupIngress | T1562 | HIGH | Yes |
| 6 | Unusual Region Activity | Various | T1078 | MEDIUM | Yes |
| 7 | IAM Reconnaissance | ListUsers, ListRoles, etc. | T1087 | MEDIUM | Yes |
| 8 | Console Login No MFA | ConsoleLogin | T1078 | MEDIUM | Manual |
| 9 | Root Account Usage | Any | T1078.004 | CRITICAL | Manual |
