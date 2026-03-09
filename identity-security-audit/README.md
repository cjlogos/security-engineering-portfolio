# Identity Security Audit

Tools for evaluating identity security posture in Active Directory and Microsoft Entra environments.

> **Complementary tool:** This audit focuses on **defensive posture and policy compliance** across hybrid environments. For **offensive attack-path analysis** (Kerberoasting, AS-REP Roasting, DCSync, delegation abuse, ACL escalation, AdminSDHolder), see the companion [AD Privilege Escalation Analyzer](../ad-privilege-analyzer/).

## Quick Start

```powershell
# Full audit (AD + Entra) with defaults
.\Invoke-IdentitySecurityAudit.ps1

# Entra-only audit
.\Invoke-IdentitySecurityAudit.ps1 -SkipAD

# AD-only audit
.\Invoke-IdentitySecurityAudit.ps1 -SkipEntra

# Custom thresholds and output path
.\Invoke-IdentitySecurityAudit.ps1 -StaleThresholdDays 120 -DormantServiceAccountDays 90 -OutputPath "C:\Reports"
```

## Prerequisites

| Environment        | Module Required                                  | Install Command                                                        |
|--------------------|--------------------------------------------------|------------------------------------------------------------------------|
| Active Directory   | `ActiveDirectory`                                | `Add-WindowsCapability -Name Rsat.ActiveDirectory* -Online`            |
| Microsoft Entra ID | `Microsoft.Graph` (Users, Identity, Applications)| `Install-Module Microsoft.Graph -Scope CurrentUser`                    |

The script will auto-detect available modules and skip checks for unavailable environments.

For Entra ID, the script connects to Microsoft Graph with the following scopes:
`User.Read.All`, `Directory.Read.All`, `Policy.Read.All`, `Application.Read.All`, `AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`

## Parameters

| Parameter                  | Default | Description                                                   |
|----------------------------|---------|---------------------------------------------------------------|
| `-OutputPath`              | `.`     | Directory for the HTML report output                          |
| `-StaleThresholdDays`      | `90`    | Days of inactivity before a user account is flagged as stale  |
| `-DormantServiceAccountDays`| `60`   | Days of inactivity before a service account is flagged        |
| `-SkipAD`                  | —       | Skip on-premises Active Directory checks                      |
| `-SkipEntra`               | —       | Skip Microsoft Entra ID checks                                |

## Security Checks

### Privileged Accounts
- **Domain Admin membership** — Flags excessive Domain Admin count (>5 = Critical)
- **Enterprise & Schema Admin exposure** — These groups should be empty in steady state
- **Over-privileged service accounts** — Service accounts in Domain/Enterprise/Schema Admins
- **Global Admin exposure** (Entra) — Flags excessive Global Admins (>5 = Critical)
- **Permanent role assignments** (Entra) — Flags environments not using PIM eligible assignments
- **Over-permissioned app registrations** (Entra) — Apps with excessive application-level API permissions

### Authentication Security
- **Password policy** — Minimum length, complexity, lockout, reversible encryption
- **Password Never Expires** — Enabled accounts with non-expiring passwords
- **Legacy authentication (NTLMv1)** — LM compatibility level audit
- **MFA enforcement** (Entra) — Per-user MFA registration coverage
- **Legacy auth blocking** (Entra) — Conditional Access policy check
- **Conditional Access gap analysis** (Entra) — Checks 6 recommended controls: MFA for admins, MFA for all, legacy auth block, compliant device, sign-in risk, user risk
- **Conditional Access exclusion audit** (Entra) — Identifies users broadly excluded from CA policies who may bypass critical security controls

### Identity Hygiene
- **Stale user accounts** — Enabled accounts with no sign-in past threshold
- **Dormant service accounts** — Service accounts/SPNs with no recent activity
- **Disabled accounts in privileged groups** — Accounts that should have been cleaned up
- **Expired app credentials** (Entra) — App registrations with expired client secrets or certificates indicating abandoned apps
- **Expiring app credentials** (Entra) — Client secrets or certificates expiring within 30 days
- **Stale guest accounts** (Entra) — B2B guests with no recent activity
- **Dormant service principals** (Entra) — Unused application service principals

## Output

### Console
Real-time color-coded findings with severity levels: Critical (red), High (orange), Medium (yellow), Low (cyan), Informational (gray).

### HTML Report
A self-contained HTML report is generated with:
- Summary dashboard (finding counts by severity)
- All findings sorted by severity (Critical first)
- Affected objects listed per finding
- Actionable recommendations for each issue

Report filename: `IdentitySecurityAudit_YYYYMMDD_HHmmss.html`

## Severity Ratings

| Severity      | Meaning                                                             |
|---------------|---------------------------------------------------------------------|
| Critical      | Immediate risk — active exploitation path or severe misconfiguration|
| High          | Significant risk — should be remediated within days                 |
| Medium        | Moderate risk — plan remediation within weeks                       |
| Low           | Minor risk — address during regular maintenance cycles              |
| Informational | No issue found — check passed or for awareness only                 |

## Relationship to AD Privilege Escalation Analyzer

| Aspect                    | This Tool (Identity Security Audit)              | AD Privilege Escalation Analyzer                      |
|---------------------------|--------------------------------------------------|-------------------------------------------------------|
| **Perspective**           | Defensive — policy & posture compliance          | Offensive — attack path discovery                     |
| **Environment**           | Hybrid (AD + Entra ID)                           | On-premises AD only                                   |
| **Key Checks**            | MFA, CA policies, credential lifecycle, hygiene  | DCSync, Kerberoast, delegation, ACL abuse, AdminSDHolder |
| **Output**                | Console + HTML report                            | 15+ granular CSV reports + unified findings           |
| **Audience**              | Security ops, compliance, leadership              | Pen testers, red team, AD security engineers          |
