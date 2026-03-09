# AD Privilege Escalation Analyzer

A PowerShell-based tool that identifies privilege escalation risks and insecure configurations in Active Directory environments. Performs automated enumeration of AD objects and highlights attack paths commonly abused during post-compromise operations.

---

## Overview

The AD Privilege Escalation Analyzer identifies common Active Directory misconfigurations that attackers exploit to gain privileged access. It performs recursive group enumeration, delegation analysis, ACL scanning, stale account detection, DCSync detection, and more — producing both detailed per-check CSV reports and a unified findings summary.

### Key Capabilities

- **Recursive nested group membership tracing** — walks every group chain to expose hidden Tier 0 access paths
- **Kerberoasting and AS-REP Roasting detection** — identifies accounts vulnerable to offline credential attacks
- **DCSync detection** — identifies non-default principals with domain replication rights (Critical severity)
- **Unconstrained and constrained delegation analysis** — flags dangerous delegation configurations on users and computers
- **Stale privileged account detection** — finds admin accounts with old passwords or no recent logon activity
- **AdminSDHolder ACL abuse detection** — identifies unauthorized permissions on the SDProp source object
- **ACL scanning on domain root, OUs, and privileged groups** — surfaces WriteDacl, WriteOwner, GenericAll, WriteMember, and ResetPassword risks
- **Orphaned adminCount detection** — finds accounts that were removed from privileged groups but still carry the adminCount=1 flag
- **LAPS coverage analysis** — identifies machines without local admin password management
- **Trust relationship enumeration** — maps trust direction, type, SID filtering, and selective authentication
- **GPO link mapping** — identifies enabled, disabled, and enforced GPO links across OUs

### Output Format

All findings are consolidated into `98-Unified-Findings.csv` in the format:

```
FindingType,Name,SamAccountName,Risk,Detail,ObjectClass
```

Individual detailed CSVs (01 through 15) provide granular data for each check, and `99-Summary.csv` provides a high-level count breakdown.

---

## Repository Structure

```
ad-privilege-analyzer/
  docs/
    methodology.md              Attack chain explanations and remediation guidance
    attack-paths-explained.md   MITRE ATT&CK mapping for each finding type
  output/
    sample-report.csv           Example unified output format
    sample-run/                 Full test harness output (mock data)
      00-Run-Metadata.csv
      01-Privileged-Groups.csv
      02-Privileged-Group-Recursive-Membership.csv
      03-Tier0-Indicators.csv
      04-AdminCount-Objects.csv
      05-Upward-Group-Trace-for-AdminCount.csv
      06-User-Risks.csv
      07-Computer-Risks.csv
      08-DCSync-Capable-Principals.csv
      09-Stale-Privileged-Accounts.csv
      10-AdminSDHolder-ACL-Risks.csv
      11-Domain-OU-PrivGroup-ACL-Risks.csv
      12-GPO-Link-Overview.csv
      13-Trust-Overview.csv
      14-LAPS-Overview.csv
      15-Delegation-Summary.csv
      98-Unified-Findings.csv
      99-Summary.csv
      README.txt
  scripts/
    Invoke-ADPrivilegeAnalyzer.ps1              Production script (requires AD module)
    Invoke-ADPrivilegeAnalyzer-TestHarness.ps1  Self-contained test with mock AD data
  README.md                                     This file
```

---

## Usage

### Production (live Active Directory)

Requires a domain-joined machine with the ActiveDirectory PowerShell module (RSAT) installed.

```powershell
Import-Module ActiveDirectory

# Basic run
.\Invoke-ADPrivilegeAnalyzer.ps1 -ShowConsoleSummary

# Full scan with all optional checks
.\Invoke-ADPrivilegeAnalyzer.ps1 -IncludeAclScan -IncludeDelegationScan -IncludeTrustScan -IncludeLapsCheck -IncludeGpoLinkScan -ShowConsoleSummary

# Custom stale thresholds
.\Invoke-ADPrivilegeAnalyzer.ps1 -IncludeAclScan -StalePasswordDays 180 -StaleLogonDays 90 -ShowConsoleSummary
```

Output is saved to `C:\caltech\AD-Privilege-Escalation-Analyzer\Run_<timestamp>\` by default.

### Test Harness (no AD required)

Runs on any Windows machine with PowerShell 5.1+. No dependencies.

```powershell
.\Invoke-ADPrivilegeAnalyzer-TestHarness.ps1
```

This builds a simulated `mocklab.local` domain with 25 users, 10 computers, and 21 groups, runs the full analysis pipeline against mock data, and validates the output with 23 automated assertions.

---

## Test Harness — Seeded Misconfigurations

The test harness deliberately plants the following misconfigurations to validate every detection path:

| # | Misconfiguration | Expected Finding | Severity |
|---|---|---|---|
| 1 | `svc_replication` has DCSync rights (DS-Replication-Get-Changes + Get-Changes-All) | DCSync-Capable Principal | CRITICAL |
| 2 | `svc_sql` is in Domain Admins and has an SPN set | Kerberoastable User (privileged) | HIGH |
| 3 | `svc_web` has an SPN set (not privileged) | Kerberoastable User | MEDIUM |
| 4 | `svc_monitor` is nested into DA via group chain and has an SPN | Kerberoastable User (privileged) + Tier 0 path | HIGH |
| 5 | `temp.contractor` has DoesNotRequirePreAuth enabled | AS-REP Roastable User | MEDIUM |
| 6 | `svc_exchange` has TrustedForDelegation on a user account | Unconstrained Delegation User | HIGH |
| 7 | `svc_proxy` has TrustedToAuthForDelegation + AllowedToDelegateTo | Constrained Delegation User | MEDIUM |
| 8 | `APP-SERVER01` has TrustedForDelegation (not a DC) | Unconstrained Delegation Computer | HIGH |
| 9 | `WEB01` has constrained delegation to HTTP service | Constrained Delegation Computer | MEDIUM |
| 10 | `old.admin` in DA with 500-day-old password, last logon 400 days ago | Stale Privileged Account | HIGH |
| 11 | `setup.admin` in DA with 600-day-old password, never logged in | Stale Privileged Account | HIGH |
| 12 | `schema.admin` in Schema Admins with 800-day-old password | Stale Privileged Account | HIGH |
| 13 | `svc_backup` in Backup Operators with 300-day-old password | Stale Privileged Account | HIGH |
| 14 | `former.admin` has adminCount=1 but is not in any privileged group | Orphaned AdminCount Account | MEDIUM |
| 15 | Group chain: IT-Admins → Server-Ops-Custom → Domain Admins (3 levels) | Nested Tier 0 path at depth 3 | HIGH |
| 16 | `svc_exchange` has GenericAll on AdminSDHolder | AdminSDHolder ACL Risk | HIGH |
| 17 | `helpdesk.lead` has WriteDacl on AdminSDHolder | AdminSDHolder ACL Risk | HIGH |
| 18 | `svc_monitor` has WriteOwner on Domain Admins group | ACL Risk on Privileged Group | HIGH |
| 19 | `dns.admin` has WriteMember on Domain Admins group | ACL Risk on Privileged Group | MEDIUM |
| 20 | `svc_proxy` has ResetPassword on domain root (inherited) | ACL Risk on Domain | HIGH |
| 21 | `helpdesk.lead` has GenericWrite on Servers OU | ACL Risk on OU | MEDIUM |
| 22 | `FILE02` and `WKS003` have no LAPS deployed | LAPS gap | — |
| 23 | External trust to `partner.corp` + child trust to `dev.mocklab.local` | Trust enumeration | — |
| 24 | 4 GPO links including 1 disabled link | GPO link mapping | — |

### Expected Test Results

```
CRITICAL : 1  (DCSync)
HIGH     : 42 (Tier 0 membership, unconstrained delegation, high-risk ACLs)
MEDIUM   : 17 (Kerberoast, constrained delegation, stale accounts, orphaned adminCount)
Total    : 60 unified findings
```

All 23 automated validation assertions should pass.

---

## Performance

The production script uses a bulk-caching strategy: all users, computers, and groups are fetched via three LDAP queries during initialization and stored in a hashtable. All subsequent operations (recursive group walking, risk checks, stale detection, LAPS checks) read from cache instead of making per-object LDAP calls. The test harness completes the full analysis of 56 objects in under 1 second.

---

## Documentation

- **[methodology.md](docs/methodology.md)** — Detailed explanation of why each check exists, how the attack works in practice, and what remediation looks like.
- **[attack-paths-explained.md](docs/attack-paths-explained.md)** — Maps every finding type to MITRE ATT&CK techniques with full attack chain narratives covering Kerberoasting, DCSync, delegation abuse, ACL-based escalation, AdminSDHolder persistence, and stale account exploitation.

---

## Important Notes

- This tool surfaces likely escalation paths; it does not prove exploitability by itself.
- Some findings may be inherited, legacy, or intentionally delegated — always validate in context.
- The sample output in `output/sample-run/` is generated from mock data (mocklab.local), not a real environment.
- **Never commit real AD scan output to a public repository.** Real output contains usernames, group structures, delegation configurations, and ACL data that would be valuable to an attacker.
