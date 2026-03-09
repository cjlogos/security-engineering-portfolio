# Attack Paths Explained — MITRE ATT&CK Mapping

This document maps each finding type produced by the AD Privilege Escalation Analyzer to the corresponding MITRE ATT&CK techniques. This mapping provides a shared language for communicating risks to security teams, SOC analysts, and leadership.

---

## Finding Type → ATT&CK Mapping

| Finding Type | MITRE Technique | Technique ID | Tactic |
|---|---|---|---|
| Kerberoastable User | Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | Credential Access |
| AS-REP Roastable User | Steal or Forge Kerberos Tickets: AS-REP Roasting | T1558.004 | Credential Access |
| DCSync-Capable Principal | OS Credential Dumping: DCSync | T1003.006 | Credential Access |
| Unconstrained Delegation (User) | Steal or Forge Kerberos Tickets: Golden Ticket | T1558.001 | Credential Access |
| Unconstrained Delegation (Computer) | Steal or Forge Kerberos Tickets: Golden Ticket | T1558.001 | Credential Access |
| Constrained Delegation (User) | Abuse Elevation Control Mechanism | T1548 | Privilege Escalation |
| Constrained Delegation (Computer) | Abuse Elevation Control Mechanism | T1548 | Privilege Escalation |
| Domain Admin / Tier 0 Membership | Valid Accounts: Domain Accounts | T1078.002 | Persistence, Privilege Escalation |
| Nested Group Privilege Path | Valid Accounts: Domain Accounts | T1078.002 | Privilege Escalation |
| Stale Privileged Account | Valid Accounts: Domain Accounts | T1078.002 | Persistence |
| Orphaned AdminCount Account | Account Manipulation | T1098 | Persistence |
| AdminSDHolder ACL Abuse | Domain Policy Modification | T1484 | Defense Evasion, Privilege Escalation |
| WriteDacl / WriteOwner on Priv Group | Account Manipulation: Additional Cloud Roles | T1098.003 | Privilege Escalation |
| WriteMember on Privileged Group | Account Manipulation | T1098 | Privilege Escalation |
| ResetPassword on Domain Root | Account Manipulation | T1098 | Privilege Escalation |
| GenericAll / GenericWrite on OU | Domain Policy Modification | T1484 | Privilege Escalation |
| No LAPS Coverage | Unsecured Credentials | T1552 | Credential Access |
| Trust with SID Filtering Disabled | Steal or Forge Kerberos Tickets: Golden Ticket | T1558.001 | Lateral Movement |
| GPO Modification Risk | Domain Policy Modification: Group Policy Modification | T1484.001 | Defense Evasion, Privilege Escalation |

---

## Detailed Attack Path Narratives

### Path 1: Kerberoasting → Domain Admin

**ATT&CK Chain:** T1558.003 → T1078.002

```
Initial Access (any domain user)
  → Credential Access: Kerberoasting (T1558.003)
    → Request TGS for SPN-bearing admin account
    → Offline password crack
  → Privilege Escalation: Domain Admin credentials (T1078.002)
    → Full domain compromise
```

**Detection:** Monitor Event ID 4769 for TGS requests using RC4 encryption (encryption type 0x17) from non-service accounts. High volumes of TGS requests from a single source in a short timeframe are a strong indicator.

**Real-world prevalence:** Kerberoasting was used in approximately 25% of red team engagements and is one of the first techniques attempted after initial domain access.

---

### Path 2: DCSync → Golden Ticket → Persistent Access

**ATT&CK Chain:** T1003.006 → T1558.001

```
Compromised account with replication rights
  → Credential Access: DCSync (T1003.006)
    → Request NTLM hash for krbtgt account
  → Credential Access: Golden Ticket (T1558.001)
    → Forge TGT for any account, any group, any lifetime
  → Persistence: Indefinite domain access
    → Survives password resets (except double krbtgt rotation)
```

**Detection:** Monitor Event ID 4662 where the Properties field contains the replication GUIDs (`1131f6aa-...` and `1131f6ad-...`) and the source is not a known domain controller. Also monitor for `DsGetNCChanges` calls from non-DC IPs at the network level.

**Critical note:** A Golden Ticket attack persists even after the compromised account's password is changed. The only remediation is to rotate the `krbtgt` password twice (to invalidate both the current and previous keys), which will briefly disrupt Kerberos authentication domain-wide.

---

### Path 3: Unconstrained Delegation → TGT Theft → DCSync

**ATT&CK Chain:** T1558.001 → T1003.006

```
Compromised server with unconstrained delegation
  → Credential Access: TGT extraction from memory
    → Wait for or coerce DA authentication (Printer Bug / PetitPotam)
  → Lateral Movement: Impersonate DA with stolen TGT
  → Credential Access: DCSync with DA privileges (T1003.006)
    → Full credential dump
```

**Detection:** Monitor for unexpected logons (Event ID 4624) to unconstrained delegation systems from privileged accounts. Deploy honeypot SPNs on delegation-enabled systems. Monitor for `SpoolSample` / `PetitPotam` coercion attempts.

---

### Path 4: ACL Abuse → Group Manipulation → Domain Admin

**ATT&CK Chain:** T1484 → T1098 → T1078.002

```
Compromised account with WriteOwner on Domain Admins
  → Defense Evasion: Take ownership of DA group (T1484)
    → Grant self WriteDacl
    → Grant self GenericAll
  → Privilege Escalation: Add self to Domain Admins (T1098)
  → Persistence: Domain Admin access (T1078.002)
```

**Detection:** Monitor Event ID 5136 (Directory Service Changes) for modifications to privileged group objects. Alert on ownership changes (Event ID 5137) for any Tier 0 object. ACL-based attacks are notoriously difficult to detect without proper auditing enabled.

---

### Path 5: AdminSDHolder Persistence → Propagation to All Protected Objects

**ATT&CK Chain:** T1484 → T1098

```
Attacker modifies AdminSDHolder ACL
  → Adds GenericAll for compromised account
  → SDProp runs every 60 minutes
    → Malicious ACE propagated to all adminCount=1 objects
  → Attacker now has GenericAll on:
    → Domain Admins group
    → Enterprise Admins group
    → Built-in Administrator account
    → All other protected objects
```

**Detection:** Monitor for ACL changes on the AdminSDHolder object specifically. This is a high-fidelity detection — legitimate changes to AdminSDHolder are extremely rare. Any modification should trigger an immediate investigation.

---

### Path 6: Nested Group Chain → Unexpected Tier 0 Access

**ATT&CK Chain:** T1078.002

```
User added to "IT-Support" group (appears low-privilege)
  → IT-Support is a member of "Server-Operations"
    → Server-Operations is a member of "Domain Admins"
  → User is now an effective Domain Admin
    → No direct DA membership visible in simple group queries
    → Only discoverable through recursive enumeration
```

**Detection:** Recursive group membership enumeration (which this tool performs) is the primary detection method. Simple `memberOf` queries miss nested chains. Tools like BloodHound also visualize these paths effectively.

---

### Path 7: Stale Account → Undetected Long-Term Compromise

**ATT&CK Chain:** T1078.002

```
Attacker discovers stale DA account (old.admin)
  → Password unchanged for 500+ days
  → No logon in 400+ days (no one monitoring it)
  → Attacker obtains credentials via:
    → Kerberoasting (if SPN set)
    → Password spraying (if weak password)
    → Credential stuffing from breach databases
  → Attacker uses account for months undetected
    → No baseline of "normal" behavior exists for comparison
```

**Detection:** Alert on authentication events for accounts that have not logged in within 90+ days. Flag and investigate any privileged account with a password older than 180 days.

---

## References

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [T1558 - Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)
- [T1003.006 - DCSync](https://attack.mitre.org/techniques/T1003/006/)
- [T1484 - Domain Policy Modification](https://attack.mitre.org/techniques/T1484/)
- [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)
- [T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
