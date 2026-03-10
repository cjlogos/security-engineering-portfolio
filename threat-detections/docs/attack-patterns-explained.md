# Authentication Attack Patterns Explained

## Overview

This document explains the three authentication attack patterns detected by the Auth Attack Detector script, including how each attack works, what distinguishes them in log data, and how to respond.

---

## 1. Brute Force (MITRE ATT&CK T1110.001)

### How It Works
An attacker targets a **single account** and systematically tries many passwords until one succeeds. Tools like Hydra, Medusa, or custom scripts automate this process, often using wordlists or permutation engines.

### Log Signature
- **High volume** of Event ID 4625 (Failed Logon) against **one account**
- Failures originate from **one or very few source IPs**
- Events are tightly clustered in time (seconds apart)
- Sub-status `0xC000006A` (incorrect password) dominates

### Example Timeline
```
08:00:01  4625  CORP\admin  from 10.0.50.101  (bad password)
08:00:03  4625  CORP\admin  from 10.0.50.101  (bad password)
08:00:05  4625  CORP\admin  from 10.0.50.101  (bad password)
...repeated 25+ times in 5 minutes...
```

### Detection Thresholds (Defaults)
| Parameter | Value |
|-----------|-------|
| Failure threshold | 10 failed logins |
| Time window | 5 minutes |
| Max source IPs | 3 |

### Response Actions
1. Lock the targeted account immediately
2. Block the source IP(s) at the firewall/WAF
3. Check for any successful logons from the same source after the attack window
4. Review whether the account has MFA enabled
5. Rotate the account password

---

## 2. Credential Stuffing (MITRE ATT&CK T1110.004)

### How It Works
Attackers use **leaked username/password pairs** from breached databases and test them against your environment. The assumption is that users reuse passwords across services. Each credential pair is tried once — if it fails, the attacker moves to the next pair.

### Log Signature
- A **single source IP** fails against **many distinct accounts**
- Approximately **one attempt per account** (low attempts-per-account ratio)
- Events are rapid and sequential
- Mix of `0xC0000064` (user doesn't exist) and `0xC000006A` (bad password)

### Example Timeline
```
09:00:00  4625  CORP\jsmith    from 198.51.100.47  (bad password)
09:00:02  4625  CORP\mjones    from 198.51.100.47  (user not found)
09:00:04  4625  CORP\admin     from 198.51.100.47  (bad password)
09:00:06  4625  CORP\svc_sql   from 198.51.100.47  (bad password)
...20+ unique accounts in 5 minutes...
```

### Detection Thresholds (Defaults)
| Parameter | Value |
|-----------|-------|
| Account threshold | 10 unique accounts |
| Time window | 5 minutes |

### What Distinguishes It from Password Spraying
- Credential stuffing: **unique password per account** (from breach data)
- Password spraying: **same password across accounts**
- In logs without password visibility, credential stuffing shows ~1 attempt per account, while spraying may show 1-3 uniform attempts per account

### Response Actions
1. Block the source IP immediately
2. Check if any targeted accounts had successful logons after the attack
3. Enforce MFA on all targeted accounts
4. Cross-reference targeted usernames against known breach databases (e.g., Have I Been Pwned)
5. Notify affected users to change passwords on all services

---

## 3. Password Spraying (MITRE ATT&CK T1110.003)

### How It Works
The attacker picks **one or two common passwords** (e.g., `Summer2025!`, `Password1`) and tries them against **many accounts**. By keeping attempts per account low, they evade account lockout policies that trigger after N failures.

### Log Signature
- A **single source** targets **many accounts**
- **Very few attempts per account** (typically 1-2)
- Events may be **spaced more widely** than brute force or stuffing
- Sub-status is consistently `0xC000006A` (bad password) — the accounts exist but the password is wrong

### Example Timeline
```
10:00:00  4625  CORP\employee1   from 203.0.113.88  (bad password)
10:00:12  4625  CORP\employee2   from 203.0.113.88  (bad password)
10:00:24  4625  CORP\employee3   from 203.0.113.88  (bad password)
...15+ accounts, max 2 attempts each, over 30 minutes...
```

### Detection Thresholds (Defaults)
| Parameter | Value |
|-----------|-------|
| Account threshold | 10 unique accounts |
| Time window | 30 minutes |
| Max attempts per account | 3 |

### Why It's Dangerous
- Stays below lockout thresholds (most orgs lock at 5-10 failures)
- Common passwords succeed more often than expected
- Often targets service accounts and admin accounts
- Can go undetected without cross-account correlation

### Response Actions
1. Block the source IP
2. Enforce MFA organization-wide
3. Audit all targeted accounts for successful logons
4. Implement smart lockout policies that correlate failures across accounts
5. Review password policy — ban common passwords via Azure AD / AD password protection

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic | Data Source |
|-----------|-----|--------|-------------|
| Brute Force: Password Guessing | T1110.001 | Credential Access | Windows Event Log 4625 |
| Brute Force: Password Spraying | T1110.003 | Credential Access | Windows Event Log 4625 |
| Brute Force: Credential Stuffing | T1110.004 | Credential Access | Windows Event Log 4625 |

---

## References

- [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Microsoft: Event 4625 — An account failed to log on](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [OWASP: Credential Stuffing](https://owasp.org/www-community/attacks/Credential_stuffing)
