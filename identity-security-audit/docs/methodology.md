# Audit Methodology

## Overview

The Identity Security Audit evaluates an organization's identity security posture across hybrid environments — on-premises Active Directory and Microsoft Entra ID. It takes a **defensive, blue-team perspective**, assessing policy compliance, configuration hygiene, and adherence to Microsoft and industry best practices.

This complements the [AD Privilege Escalation Analyzer](../../ad-privilege-analyzer/), which takes an offensive approach to mapping attack paths.

## Audit Phases

### Phase 1 — Privileged Account Assessment

The audit begins by enumerating privileged group memberships and evaluating whether the organization follows the principle of least privilege.

**Active Directory checks:**
- Domain Admin, Enterprise Admin, and Schema Admin group membership counts are compared against recommended thresholds. Enterprise and Schema Admins should be empty during normal operations.
- Service accounts (identified by SPN, naming convention `svc_`, `svc-`, `service_`, `sa_`) are checked for membership in privileged groups — a common misconfiguration that creates unnecessary blast radius.

**Entra ID checks:**
- Global Administrator count is compared against Microsoft's recommendation of fewer than 5.
- All privileged role assignments (Global Admin, User Admin, Exchange Admin, etc.) are evaluated for permanent vs. PIM-eligible status. Permanent assignments bypass approval workflows and create standing privilege.
- App registrations are reviewed for excessive application-level (Role) API permissions, which grant broad access without user context.

### Phase 2 — Authentication Security

This phase evaluates whether authentication controls are properly configured to resist credential-based attacks.

**Active Directory checks:**
- Default domain password policy is assessed: minimum length (14+ recommended), complexity, lockout thresholds, and reversible encryption.
- Accounts with "Password Never Expires" are flagged — these are often service accounts that should be migrated to Group Managed Service Accounts (gMSA).
- LAN Manager compatibility level is checked to determine whether NTLMv1 (vulnerable to relay and cracking) is permitted.

**Entra ID checks:**
- Per-user MFA registration is audited by querying authentication methods. Accounts with only password-based authentication are flagged. Coverage percentage determines severity (below 80% = Critical, below 95% = High).
- Conditional Access policies are checked for a legacy authentication blocking rule. Legacy auth protocols (Exchange ActiveSync, older Office clients) bypass MFA entirely.
- A gap analysis checks for 6 recommended Conditional Access controls: MFA for admins, MFA for all users, legacy auth blocking, compliant device requirement, sign-in risk policy, and user risk policy.
- User exclusions across all CA policies are analyzed. Users excluded from more than half of all enabled policies may bypass critical security controls.

### Phase 3 — Identity Hygiene

The final phase identifies lifecycle management failures that expand the attack surface over time.

**Active Directory checks:**
- Stale user accounts (enabled but no sign-in past the configurable threshold, default 90 days) indicate poor offboarding processes.
- Dormant service accounts (identified by SPN or naming convention, no activity past threshold) represent unmanaged attack surface.
- Disabled accounts still present in privileged groups are flagged — these should have been cleaned up during deprovisioning.

**Entra ID checks:**
- Stale member users and guest accounts are identified via sign-in activity timestamps.
- App registration credentials (client secrets and certificates) are checked for expiry. Expired credentials indicate abandoned applications. Credentials expiring within 30 days trigger a proactive warning.
- Dormant service principals (application type with no recent sign-in) indicate unused integrations that should be removed.

## Severity Framework

| Severity      | Criteria                                                                                       | Expected Response Time |
|---------------|-----------------------------------------------------------------------------------------------|------------------------|
| Critical      | Directly exploitable or violates a fundamental security control (e.g., no legacy auth blocking) | Immediate (24-48 hrs)  |
| High          | Significant misconfiguration or policy gap that increases risk materially                      | Days (1-2 weeks)       |
| Medium        | Moderate risk, often a hygiene issue that accumulates over time                                 | Weeks (1 month)        |
| Low           | Minor finding, address during regular maintenance                                               | Next maintenance cycle |
| Informational | Check passed or awareness-only                                                                  | No action required     |

Thresholds are intentionally opinionated based on Microsoft's published guidance and common enterprise security baselines (CIS Benchmarks, NIST 800-63B).

## Data Sources

| Source                        | Module                          | Data Retrieved                                                |
|-------------------------------|----------------------------------|---------------------------------------------------------------|
| Active Directory              | `ActiveDirectory` (RSAT)        | Group membership, user properties, password policy, registry  |
| Microsoft Entra ID            | `Microsoft.Graph` (PowerShell)  | Users, roles, CA policies, auth methods, apps, service principals |

The script requires read-only access. No changes are made to any directory objects.
