AD Privilege Escalation Analyzer - TEST HARNESS Output
======================================================
THIS OUTPUT WAS GENERATED FROM MOCK DATA - NOT A REAL AD ENVIRONMENT.

Run path : .\TestOutput\Run_20260309_101759
Executed : 03/09/2026 10:17:59
Domain   : mocklab.local (MOCKLAB) [SIMULATED]

Mock Environment Summary
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Users      : 25  (including admins, service accounts, stale accounts, delegation abuse)
Computers  : 10  (including DCs, unconstrained/constrained delegation, LAPS mixed)
Groups     : 21  (19 well-known + 2 custom nested groups for recursion testing)

Deliberate Misconfigurations Seeded
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
1.  DCSync rights on svc_replication          -> should appear as CRITICAL in unified
2.  Kerberoastable admin (svc_sql in DA)      -> HIGH Kerberoast finding
3.  Kerberoastable non-admin (svc_web)        -> MEDIUM Kerberoast finding
4.  Kerberoastable nested admin (svc_monitor) -> HIGH Kerberoast + Tier0 path
5.  AS-REP Roastable (temp.contractor)        -> MEDIUM AS-REP finding
6.  Unconstrained delegation user (svc_exchange)         -> HIGH
7.  Constrained delegation user (svc_proxy)              -> MEDIUM
8.  Unconstrained delegation computer (APP-SERVER01)     -> HIGH
9.  Constrained delegation computer (WEB01)              -> MEDIUM
10. Stale DA: old.admin (pwd 500d, logon 400d)           -> HIGH stale
11. Stale DA: setup.admin (pwd 600d, never logged in)    -> HIGH stale
12. Stale Schema Admin: schema.admin (pwd 800d, logon 700d) -> HIGH stale
13. Stale Backup Op: svc_backup (pwd 300d, logon 250d)  -> HIGH stale
14. Orphaned adminCount: former.admin (not in any group) -> MEDIUM orphan
15. 3-level nesting: IT-Admins -> Server-Ops-Custom -> Domain Admins
16. AdminSDHolder ACL: svc_exchange has GenericAll       -> HIGH ACL
17. AdminSDHolder ACL: helpdesk.lead has WriteDacl       -> HIGH ACL
18. DA group: svc_monitor has WriteOwner                 -> HIGH ACL
19. DA group: dns.admin can WriteMember                  -> MEDIUM ACL
20. Domain root: svc_proxy has ResetPassword             -> HIGH ACL
21. OU Servers: helpdesk.lead has GenericWrite            -> MEDIUM ACL
22. 2 computers with no LAPS (FILE02, WKS003)
23. 2 AD trusts (1 external, 1 parent-child)
24. 4 GPO links (1 disabled)

Validation Checklist
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
[ ] 98-Unified-Findings.csv has CRITICAL/HIGH/MEDIUM findings
[ ] Nested group chain appears in 02-Recursive-Membership and 03-Tier0
[ ] Stale accounts appear in 09-Stale with correct reasons
[ ] DCSync appears in 08-DCSync with svc_replication flagged Critical
[ ] former.admin appears as orphaned adminCount in unified
[ ] LAPS shows FILE02 and WKS003 as AnyLAPSDetected=False
[ ] Delegation summary includes both user and computer findings
[ ] All 19 well-known groups appear in 01-Privileged-Groups.csv
