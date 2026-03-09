# AD Privilege Escalation Analyzer — Methodology

## Purpose

This document explains the reasoning behind each check performed by the AD Privilege Escalation Analyzer. For every detection, it covers three things: **why** this configuration is dangerous, **how** an attacker exploits it in practice, and **what** defenders should do about it. The goal is not just to enumerate misconfigurations but to demonstrate understanding of the full attack chain from initial access through domain compromise.

---

## 1. Privileged Group Membership & Nested Group Recursion

### What We Check

The analyzer identifies all well-known privileged groups (Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators, Server Operators, DnsAdmins, etc.) and recursively walks every nested group chain to map the complete set of principals with privileged access.

### Why This Matters

Active Directory group nesting is one of the most common sources of unintended privilege escalation. A user might be placed into a benign-sounding group like "IT-Support" without anyone realizing that IT-Support is nested inside Server-Ops, which is nested inside Domain Admins. The user now has full domain admin rights through a chain nobody is actively monitoring.

### Real-World Exploitation

An attacker who compromises any account in a nested chain effectively has the privileges of the root group. During post-compromise reconnaissance (often using tools like BloodHound or PowerView), attackers map these paths specifically because nested memberships are frequently overlooked by defenders. A three-level nesting chain like `IT-Admins → Server-Ops → Domain Admins` means compromising any IT-Admins member grants Domain Admin access.

### Remediation

- Audit all nested group memberships quarterly. Remove unnecessary nesting.
- Implement a tiered administration model where Tier 0 groups (DA, EA, SA) contain only direct members, never nested groups.
- Use the recursive membership output from this tool to visualize and flatten group chains.
- Set alerts on group membership changes for all Tier 0 groups.

---

## 2. Kerberoasting Detection

### What We Check

The analyzer identifies all user accounts that have a `servicePrincipalName` (SPN) set. It flags these as Kerberoastable, with elevated severity (High) if the account also has `adminCount=1`, indicating it is or was a member of a privileged group.

### Why This Matters

Any domain user can request a Kerberos TGS (Ticket Granting Service) ticket for any SPN in the domain. The ticket is encrypted with the service account's password hash. The attacker can then take this ticket offline and crack it with tools like Hashcat or John the Ripper with no further interaction with the domain controller. If the service account has a weak password, the attacker now has those credentials.

### Real-World Exploitation

Kerberoasting is one of the most common privilege escalation techniques in real-world engagements. The attack sequence is:

1. Attacker gains access to any authenticated domain account (even a low-privilege user).
2. Attacker runs `GetUserSPNs.py` (Impacket) or `Invoke-Kerberoast` (PowerSploit) to request TGS tickets for all SPN-bearing user accounts.
3. Attacker cracks the tickets offline. Service accounts frequently have weak or never-rotated passwords.
4. If the cracked account is a member of Domain Admins (adminCount=1), the attacker now has DA credentials.

A Kerberoastable account with adminCount=1 is the worst-case scenario: a single offline password crack away from full domain compromise.

### Remediation

- Remove SPNs from user accounts where possible. Use machine accounts (which have 120+ character random passwords) for services instead.
- For user accounts that must have SPNs, enforce 25+ character randomly generated passwords and rotate them every 30 days.
- Use Group Managed Service Accounts (gMSAs) which handle password rotation automatically.
- Monitor for anomalous TGS requests (Event ID 4769) where the encryption type is RC4, which is the type attackers request because it is fastest to crack.
- Move privileged service accounts into the Protected Users group to prevent Kerberos ticket requests using RC4.

---

## 3. AS-REP Roasting Detection

### What We Check

The analyzer identifies accounts with the `DoesNotRequirePreAuth` flag set, which disables Kerberos pre-authentication.

### Why This Matters

Kerberos pre-authentication normally requires the client to prove knowledge of the password before the KDC issues an AS-REP (Authentication Service Reply). When pre-authentication is disabled, anyone can request an AS-REP for that account, and the response contains material encrypted with the user's password hash — crackable offline, just like Kerberoasting.

### Real-World Exploitation

1. Attacker enumerates accounts with pre-auth disabled using `GetNPUsers.py` (Impacket) or LDAP queries.
2. Attacker requests an AS-REP for each account — no credentials required, just network access.
3. The encrypted portion of the AS-REP is cracked offline.
4. If the account is privileged, the attacker gains elevated access immediately.

This is often seen on legacy accounts, service accounts configured by admins who didn't understand the security implications, or contractor accounts set up for "convenience."

### Remediation

- Require Kerberos pre-authentication on all accounts. There is almost never a legitimate reason to disable it.
- Audit for this flag regularly: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`.
- If pre-auth must be disabled for a legacy application, ensure the account has a very strong password and is not a member of any privileged group.

---

## 4. DCSync Detection

### What We Check

The analyzer reads the ACL on the domain root object and identifies any principal that holds both `DS-Replication-Get-Changes` (GUID `1131f6aa-...`) and `DS-Replication-Get-Changes-All` (GUID `1131f6ad-...`). A principal with both rights can perform a DCSync attack. Expected principals (Domain Controllers, Enterprise Domain Controllers, Administrators) are flagged as informational; any non-default principal is flagged as Critical.

### Why This Matters

DCSync allows an attacker to impersonate a domain controller and request password hashes for any account in the domain, including the `krbtgt` account. With the `krbtgt` hash, the attacker can forge Golden Tickets and maintain persistent, undetectable domain access indefinitely.

### Real-World Exploitation

1. Attacker compromises an account that has replication rights on the domain root (either through direct ACL assignment or through GenericAll / AllExtendedRights).
2. Attacker runs `secretsdump.py` (Impacket) or `Invoke-Mimikatz -Command '"lsadump::dcsync /domain:target.local /user:krbtgt"'`.
3. The domain controller responds with the full password hash for the requested account.
4. With the `krbtgt` hash, the attacker forges Golden Tickets — valid Kerberos TGTs for any account, with any group membership, for any duration.

This is one of the most severe findings possible. A non-default principal with DCSync rights almost always indicates either a compromise that has already occurred or a critically misconfigured delegation.

### Remediation

- Immediately audit any non-default principal with replication rights. Remove the rights unless there is a documented, approved business reason.
- Monitor for DCSynC activity: Event ID 4662 with the replication GUIDs in the Properties field.
- Regularly audit the domain root ACL: `(Get-Acl "AD:\DC=domain,DC=local").Access | Where-Object { $_.ObjectType -match '1131f6a' }`.
- Consider deploying a DCSync detection tool or SIEM rule that alerts on replication requests from non-DC IP addresses.

---

## 5. Unconstrained Delegation

### What We Check

The analyzer flags user and computer accounts with `TrustedForDelegation = True`. Domain controllers are expected to have this flag; any other system with unconstrained delegation is flagged as High severity.

### Why This Matters

A machine with unconstrained delegation stores the TGT (Ticket Granting Ticket) of every user who authenticates to it. If an attacker compromises that machine, they can extract those cached TGTs and impersonate any user who has connected — including domain administrators.

### Real-World Exploitation

1. Attacker compromises a server with unconstrained delegation (e.g., a web server, application server, or print server).
2. Attacker uses Rubeus or Mimikatz to dump TGTs from memory.
3. If a Domain Admin has authenticated to that server (via RDP, file share access, or any Kerberos-authenticated service), their TGT is cached.
4. Attacker injects the DA's TGT and now operates as that DA.

The "Printer Bug" (SpoolSample) technique can also be used to coerce a domain controller into authenticating to the compromised server, delivering the DC's machine account TGT — which can then be used for DCSync.

### Remediation

- Remove unconstrained delegation from all non-DC systems. Replace with constrained delegation or resource-based constrained delegation (RBCD).
- Add privileged accounts to the Protected Users group, which prevents their TGTs from being cached on delegation-enabled systems.
- Mark sensitive accounts as "Account is sensitive and cannot be delegated."
- Monitor for TGT extraction: Event ID 4624 (logon type 10 or 3) to delegation-enabled systems from privileged accounts.

---

## 6. Constrained Delegation

### What We Check

The analyzer identifies accounts with `TrustedToAuthForDelegation = True` or with `msDS-AllowedToDelegateTo` populated, flagged as Medium severity.

### Why This Matters

Constrained delegation allows an account to impersonate any user to specific services listed in `msDS-AllowedToDelegateTo`. While more restricted than unconstrained delegation, protocol transition (`TrustedToAuthForDelegation`) allows the account to impersonate users who never actually authenticated to it — significantly expanding the attack surface.

### Real-World Exploitation

1. Attacker compromises a service account with constrained delegation configured for protocol transition.
2. Attacker uses Rubeus `s4u` to request a TGS for any user (including Domain Admins) to the allowed target services.
3. The attacker can now access those services as the impersonated user.
4. If the allowed service is `cifs/fileserver`, the attacker can access file shares as a DA. If it's `ldap/dc`, the attacker can perform LDAP operations as a DA.

### Remediation

- Audit all `msDS-AllowedToDelegateTo` values. Ensure the delegation target is the minimum necessary.
- Avoid protocol transition (`TrustedToAuthForDelegation`) unless absolutely required.
- Prefer resource-based constrained delegation (RBCD) which is configured on the target rather than the source, giving resource owners control.
- Use the Protected Users group for accounts that should never be delegated.

---

## 7. Stale Privileged Accounts

### What We Check

The analyzer cross-references all users found in privileged group memberships with their `pwdLastSet` and `lastLogonTimestamp` values. Accounts with passwords older than a configurable threshold (default: 365 days) or with no logon activity beyond another threshold (default: 180 days) are flagged. Accounts that fail both checks receive High severity.

### Why This Matters

Stale privileged accounts are prime targets for attackers. An account with a password that hasn't been changed in years is more likely to have been compromised without anyone noticing. An account that nobody has logged into for months is an account nobody is monitoring. If an attacker uses it, the activity may go unnoticed for a long time.

### Real-World Exploitation

1. Attacker discovers a stale service account with DA membership through LDAP enumeration.
2. The account was created during a migration two years ago and forgotten. Its password has never been rotated.
3. Attacker Kerberoasts the account (if it has an SPN) or finds the password in a previous breach database.
4. Because nobody monitors the account, the attacker uses it for months without detection.

Setup accounts and "break glass" accounts are common offenders — created during initial domain setup and never decommissioned.

### Remediation

- Disable or remove privileged accounts that are no longer in active use.
- Enforce password rotation policies on all privileged accounts (maximum 90 days for Tier 0).
- Set up alerts for logons by accounts that have not been active in 90+ days.
- Conduct quarterly privileged access reviews: every account in DA, EA, SA must have an identified owner and documented purpose.

---

## 8. AdminCount and Orphaned AdminCount Detection

### What We Check

The analyzer enumerates all objects with `adminCount=1` and cross-references them against current privileged group membership. Objects that have `adminCount=1` but are no longer in any privileged group are flagged as "Orphaned AdminCount" findings.

### Why This Matters

When an object is added to a privileged group, the SDProp process sets `adminCount=1` and replaces the object's ACL with a hardened version copied from AdminSDHolder. However, when the object is *removed* from the privileged group, SDProp does NOT clear the flag or restore the original ACL. This leaves the account in an awkward state: it has a hardened ACL that may prevent legitimate administration (like password resets by the help desk), but it also indicates that the account *was* privileged at some point.

### Real-World Exploitation

Orphaned adminCount accounts tell an attacker which accounts were previously privileged. These accounts may still have residual access, cached credentials in memory on servers they previously administered, or passwords from when they were privileged that have never been changed.

### Remediation

- For each orphaned adminCount object, manually clear the `adminCount` attribute and reset the ACL to inherit from the parent OU.
- Investigate whether the account still has any residual access or cached sessions.
- Rotate the password for any account that was previously privileged.

---

## 9. AdminSDHolder ACL Abuse

### What We Check

The analyzer reads the ACL on the `AdminSDHolder` object (`CN=AdminSDHolder,CN=System,DC=domain,DC=local`) and identifies non-default principals with dangerous permissions like GenericAll, WriteDacl, or WriteOwner.

### Why This Matters

Every 60 minutes, the SDProp process copies the ACL from AdminSDHolder to all objects with `adminCount=1`. If an attacker can modify the AdminSDHolder ACL, those modifications will automatically propagate to every protected object in the domain — including the Domain Admins group, the Administrator account, and all other privileged objects.

### Real-World Exploitation

1. Attacker gains WriteDacl on AdminSDHolder (perhaps through a compromised service account with excessive permissions).
2. Attacker adds an ACE granting themselves GenericAll on AdminSDHolder.
3. Within 60 minutes, SDProp copies this ACE to every protected object.
4. Attacker now has GenericAll on Domain Admins, the built-in Administrator account, and all other Tier 0 objects — enabling them to add themselves to DA, reset the Administrator password, or perform any other action.

This is a highly stealthy persistence mechanism because the malicious ACE lives on AdminSDHolder, not on the individual objects, making it harder to detect during routine ACL reviews.

### Remediation

- Audit the AdminSDHolder ACL regularly. The only principals with write access should be SYSTEM and the built-in Administrators group.
- Monitor for changes to the AdminSDHolder object: Event ID 5136 (Directory Service Changes) on the AdminSDHolder DN.
- Remove any non-default permissions immediately and investigate how they were placed.

---

## 10. Domain Root, OU, and Privileged Group ACL Risks

### What We Check

The analyzer scans ACLs on the domain root object, all organizational units, and critical privileged groups (Domain Admins, Enterprise Admins, etc.) for dangerous permissions held by non-default principals. Dangerous permissions include GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteMember, and ResetPassword.

### Why This Matters

ACL-based attacks are among the most difficult to detect because they abuse legitimate Active Directory functionality. An attacker with WriteOwner on the Domain Admins group can take ownership, grant themselves WriteDacl, then grant themselves GenericAll, then add their account as a member — all without triggering most conventional monitoring.

### Real-World Exploitation

**WriteMember on Domain Admins:** Attacker directly adds their compromised account to DA.

**WriteOwner on a privileged group:** Attacker takes ownership → grants themselves WriteDacl → grants GenericAll → adds themselves to the group.

**GenericWrite on an OU:** Attacker modifies objects in the OU, potentially adding a malicious script to GPO processing or modifying user objects.

**ResetPassword on domain root (inherited to descendants):** Attacker can reset the password of any user in the domain, including Domain Admins.

### Remediation

- Audit ACLs on the domain root, all OUs containing privileged accounts, and all Tier 0 groups.
- Remove any unnecessary permissions. Follow the principle of least privilege.
- Use AdminSDHolder as a protection mechanism — ensure privileged objects are properly flagged so SDProp enforces their ACLs.
- Deploy ACL change monitoring through Directory Service auditing (Event IDs 5136, 5137, 5138, 5139).

---

## 11. LAPS Coverage

### What We Check

The analyzer checks every computer object for the presence of Legacy LAPS (`ms-Mcs-AdmPwdExpirationTime`) and Windows LAPS (`msLAPS-PasswordExpirationTime`, `msLAPS-EncryptedPassword`) attributes to determine which machines have LAPS deployed and which do not.

### Why This Matters

Without LAPS, local administrator passwords are typically identical across many machines (set during imaging). Compromising one machine's local admin password grants the attacker local admin on every machine with the same password — enabling rapid lateral movement.

### Remediation

- Deploy LAPS (preferably Windows LAPS) to all domain-joined workstations and servers.
- Ensure LAPS password retrieval is restricted to authorized administrators only.
- Machines without LAPS should be prioritized for deployment, especially servers.

---

## 12. Trust Relationships

### What We Check

The analyzer enumerates all AD trust relationships including direction, type, transitivity, selective authentication, and SID filtering status.

### Why This Matters

Trusts extend the authentication boundary. A bidirectional trust with SID filtering disabled allows an attacker who compromises one domain to forge tickets with SID history containing privileged SIDs from the trusted domain — effectively granting cross-domain admin access.

### Remediation

- Enable SID filtering (quarantine) on all external trusts.
- Use selective authentication where possible to limit which accounts can authenticate across the trust.
- Audit intra-forest trusts — parent-child trusts in the same forest inherently share the same Enterprise Admins, so compromising any domain in the forest compromises the forest.

---

## 13. GPO Link Mapping

### What We Check

The analyzer maps all GPO links to OUs and the domain root, including whether each link is enabled and whether it is enforced.

### Why This Matters

GPOs control security policy across the domain. An attacker who can modify a GPO linked to a privileged OU (like Domain Controllers) can push malicious scripts, scheduled tasks, or security policy changes to every object in that OU. Disabled or orphaned GPO links may indicate abandoned policies that could be reactivated by an attacker.

### Remediation

- Audit GPO permissions: who can modify each GPO?
- Remove disabled GPO links that are no longer needed.
- Monitor for GPO modifications: Event ID 5136 on Group Policy objects.
- Ensure GPOs linked to the Domain Controllers OU and domain root are tightly controlled.
