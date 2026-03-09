# Security Checks Explained

A detailed breakdown of every check performed by the Identity Security Audit tool, why it matters, and how to remediate.

---

## Privileged Accounts

### Excessive Domain Admins
- **What it checks:** Count of members (including nested) in the Domain Admins group.
- **Why it matters:** Domain Admins have unrestricted control over every object in the domain. Each additional member increases the attack surface — compromising any one of them gives an attacker full domain control.
- **Threshold:** More than 5 = Critical. More than 2 = Medium.
- **Remediation:** Remove unnecessary memberships. Use delegated admin models (e.g., OU-level permissions) for day-to-day tasks. Reserve Domain Admin for break-glass scenarios.

### Enterprise Admin Exposure
- **What it checks:** Whether the Enterprise Admins group has any members.
- **Why it matters:** Enterprise Admins have forest-wide control. This group should only be populated during active forest-level operations (schema upgrades, trust creation).
- **Threshold:** Any member = High.
- **Remediation:** Remove all permanent members. Use just-in-time elevation when forest-level changes are needed.

### Schema Admin Exposure
- **What it checks:** Whether the Schema Admins group has any members.
- **Why it matters:** Schema modifications are rare (typically only during Exchange installs or AD upgrades). Standing membership is unnecessary risk.
- **Threshold:** Any member = High.
- **Remediation:** Remove all members. Add temporarily only when schema changes are required.

### Over-Privileged Service Accounts
- **What it checks:** Service accounts (identified by SPN or naming convention) that are members of Domain Admins, Enterprise Admins, Schema Admins, or Administrators.
- **Why it matters:** Service accounts often have weak passwords, no MFA, and credentials stored in scripts or config files. Granting them admin privileges means a single compromised config file can yield domain admin access.
- **Threshold:** Any found = Critical.
- **Remediation:** Remove from privileged groups. Grant only the specific permissions required. Migrate to Group Managed Service Accounts (gMSA) for automatic password rotation.

### Excessive Global Admins (Entra)
- **What it checks:** Count of users assigned the Global Administrator role in Entra ID.
- **Why it matters:** Global Admins can modify any setting in the tenant, including security policies, other admin roles, and Conditional Access. Microsoft explicitly recommends fewer than 5.
- **Threshold:** More than 5 = Critical. More than 2 = Medium.
- **Remediation:** Reduce to 2-4 accounts. Assign least-privileged roles (User Admin, Exchange Admin) for specific tasks.

### Excessive Permanent Role Assignments (Entra)
- **What it checks:** Total count of permanent (active) privileged role assignments across 8 key roles.
- **Why it matters:** Permanent assignments provide standing privilege. If an account is compromised, the attacker immediately has that role's access. PIM-eligible assignments require explicit activation with justification and approval.
- **Threshold:** More than 10 = High.
- **Remediation:** Convert permanent assignments to PIM-eligible. Configure activation to require justification, approval, and MFA.

### Over-Permissioned App Registrations (Entra)
- **What it checks:** App registrations with more than 5 application-level (Role) permissions on any resource.
- **Why it matters:** Application permissions are granted without user context — they apply to all users/data. An app with `Mail.ReadWrite`, `User.ReadWrite.All`, and `Directory.ReadWrite.All` can read every mailbox and modify every user without any human signing in.
- **Threshold:** More than 5 app permissions = High.
- **Remediation:** Reduce to minimum required permissions. Use delegated permissions (which require a signed-in user) where possible.

---

## Authentication Security

### Weak Minimum Password Length
- **What it checks:** The default domain password policy's minimum length.
- **Why it matters:** Short passwords are vulnerable to brute-force and dictionary attacks. NIST SP 800-63B recommends a minimum of 8, but modern guidance (including Microsoft) recommends 14+.
- **Threshold:** Below 14 = High.
- **Remediation:** Increase to 14+ characters. Consider enabling passphrases.

### Password Complexity Disabled
- **What it checks:** Whether AD password complexity requirements are enforced.
- **Why it matters:** Without complexity, users can set passwords like `password` or `123456`.
- **Threshold:** Disabled = High.
- **Remediation:** Enable complexity or deploy a third-party password filter (e.g., Azure AD Password Protection).

### No Account Lockout Policy
- **What it checks:** Whether the account lockout threshold is configured (non-zero).
- **Why it matters:** Without lockout, attackers can attempt unlimited password guesses against any account.
- **Threshold:** Threshold of 0 = High.
- **Remediation:** Set to 10-20 attempts with a 30-minute lockout duration. Balance security with usability.

### Reversible Encryption Enabled
- **What it checks:** Whether passwords are stored with reversible encryption.
- **Why it matters:** Reversible encryption means passwords can be recovered in plaintext from the AD database. This is almost never required.
- **Threshold:** Enabled = Critical.
- **Remediation:** Disable immediately. Only enable if a specific application absolutely requires it (and plan to migrate that application).

### Password Never Expires
- **What it checks:** Enabled accounts with the "Password Never Expires" flag set.
- **Why it matters:** Non-rotating passwords increase the window for credential theft and reuse. Service accounts are the most common offenders.
- **Threshold:** Any found = Medium.
- **Remediation:** For service accounts, migrate to gMSA (automatic 30-day rotation). For user accounts, enforce rotation or use risk-based password change policies.

### Legacy Authentication — NTLMv1
- **What it checks:** The LAN Manager compatibility level in the registry.
- **Why it matters:** NTLMv1 uses weak cryptography vulnerable to relay attacks, pass-the-hash, and offline cracking. Level 5 ensures only NTLMv2 is used.
- **Threshold:** Below 5 = High.
- **Remediation:** Set `LmCompatibilityLevel` to 5. Test application compatibility first — some legacy apps may break.

### MFA Not Registered (Entra)
- **What it checks:** Per-user MFA method registration by querying authentication methods and filtering out password-only users.
- **Why it matters:** Accounts without MFA are vulnerable to credential stuffing, phishing, and password spray attacks. MFA blocks 99.9% of account compromise attempts.
- **Threshold:** Below 80% coverage = Critical. Below 95% = High. Below 100% = Medium.
- **Remediation:** Enable Security Defaults or create a Conditional Access policy requiring MFA registration. Target 100% of member accounts.

### Legacy Authentication Not Blocked (Entra)
- **What it checks:** Whether any enabled Conditional Access policy blocks legacy authentication client types (Exchange ActiveSync, "other").
- **Why it matters:** Legacy auth protocols don't support MFA. Even if you require MFA for all users, attackers can authenticate via legacy protocols and bypass it entirely. This is one of the most commonly exploited gaps.
- **Threshold:** Not blocked = Critical.
- **Remediation:** Create a CA policy targeting all users, all cloud apps, with client app condition "Exchange ActiveSync" and "Other clients", grant control = Block.

### Conditional Access Gaps (Entra)
- **What it checks:** Presence of 6 recommended CA controls: MFA for admins, MFA for all users, legacy auth block, compliant device, sign-in risk policy, user risk policy.
- **Why it matters:** Each missing control represents an unprotected attack vector. Together, these 6 controls form a baseline Zero Trust posture.
- **Threshold:** 4+ gaps = Critical. 2+ = High. 1 = Medium.
- **Remediation:** Implement missing policies. Start with legacy auth blocking and MFA for admins as highest-priority items.

### Broadly Excluded CA Users (Entra)
- **What it checks:** Users who are explicitly excluded from more than half of all enabled CA policies.
- **Why it matters:** Exclusions are often added as "temporary" workarounds and never removed. A user excluded from MFA, device compliance, and risk policies has almost no security controls applied to their account.
- **Threshold:** Any broadly excluded user = High.
- **Remediation:** Review all exclusions. Use a dedicated, monitored break-glass account group instead of excluding individual users. Set calendar reminders to revisit exclusions.

---

## Identity Hygiene

### Stale User Accounts
- **What it checks:** Enabled AD accounts where `LastLogonTimestamp` is older than the configured threshold (default: 90 days).
- **Why it matters:** Stale accounts belong to former employees, contractors, or role changes. They're prime targets for attackers because no one monitors them.
- **Threshold:** 50+ stale = High. 20+ = Medium. Any = Low.
- **Remediation:** Disable immediately. Delete after a grace period. Implement automated lifecycle management tied to HR systems.

### Dormant Service Accounts
- **What it checks:** Service accounts (by SPN or naming convention) that are enabled but have no sign-in activity past the dormant threshold (default: 60 days).
- **Why it matters:** Dormant service accounts may have standing permissions but no active monitoring. They're often created for projects that were decommissioned without cleanup.
- **Threshold:** Any found = High.
- **Remediation:** Disable dormant accounts. Verify with application owners before deletion. Migrate active service accounts to gMSA.

### Disabled Accounts in Privileged Groups
- **What it checks:** Disabled user accounts that still have membership in privileged groups (Domain Admins, Enterprise Admins, Administrators, etc.).
- **Why it matters:** If a disabled account is re-enabled (accidentally or maliciously), it immediately inherits privileged access. Clean deprovisioning should include group removal.
- **Threshold:** Any found = Medium.
- **Remediation:** Remove from all privileged groups immediately. Update offboarding procedures to include group cleanup.

### Expired App Credentials (Entra)
- **What it checks:** App registrations with client secrets or certificates past their expiration date.
- **Why it matters:** Expired credentials indicate the app is either abandoned (should be deleted) or has poor lifecycle management (risk of outage when rotated last-minute). Abandoned apps with standing API permissions are a hidden attack surface.
- **Threshold:** Any expired = High.
- **Remediation:** For abandoned apps: remove credentials, revoke permissions, delete registration. For active apps: rotate and set monitoring alerts for future expiry.

### Expiring App Credentials (Entra)
- **What it checks:** Client secrets or certificates expiring within 30 days.
- **Why it matters:** Proactive warning to prevent service disruptions and last-minute emergency rotations.
- **Threshold:** Any expiring = Medium.
- **Remediation:** Rotate credentials now. Use managed identities (which don't require credential management) where possible.

### Stale Entra ID Users
- **What it checks:** Enabled Entra ID member accounts with no `LastSignInDateTime` activity past the threshold.
- **Why it matters:** Same risk as on-prem stale accounts, but with potential access to cloud resources, SaaS apps, and data.
- **Threshold:** 50+ = High. 20+ = Medium. Any = Low.
- **Remediation:** Disable stale accounts. Enable Entra ID Access Reviews for automated lifecycle management.

### Stale Guest Accounts (Entra)
- **What it checks:** B2B guest accounts with no sign-in activity past the threshold.
- **Why it matters:** Guest accounts often have access to SharePoint sites, Teams channels, and applications. Stale guests from former partnerships or projects retain that access indefinitely.
- **Threshold:** Any stale guests = Medium.
- **Remediation:** Remove stale guests. Implement quarterly Access Reviews for all B2B guest accounts.

### Dormant Service Principals (Entra)
- **What it checks:** Application-type service principals with no sign-in activity past the dormant threshold.
- **Why it matters:** Dormant service principals may retain API permissions granted during setup. They represent an unmonitored attack surface — if an attacker obtains the app's credentials, they inherit all granted permissions.
- **Threshold:** 20+ dormant = High. Any = Medium.
- **Remediation:** Review and delete unused service principals. Remove associated app registrations. Audit remaining permissions.
