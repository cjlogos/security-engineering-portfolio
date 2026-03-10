# Threat Detection Library

Collection of detection engineering logic for identifying suspicious activity in enterprise environments.

## Detection Categories

### Authentication Attacks
- Brute force login attempts
- Credential stuffing
- Password spraying

### Privilege Escalation
- User added to privileged groups
- Delegation changes
- Service account misuse

### Suspicious PowerShell Activity
- Encoded commands
- Download cradles
- Execution policy bypass

## Log Sources

- Windows Security Event Logs
- PowerShell Operational Logs
- Active Directory Audit Logs

## Repository Structure

```
threat-detections/
├── docs/
│   ├── attack-patterns-explained.md   # Detailed breakdown of each attack type
│   └── methodology.md                 # Detection logic, thresholds, and tuning guide
├── output/
│   ├── sample-run/
│   │   ├── sample-events.json         # Synthetic input events (demo data)
│   │   └── sample-detections.json     # Detection output from sample run
│   └── sample-report.csv              # CSV report from sample run
├── scripts/
│   ├── auth_attack_detector.py        # Main detection script
│   ├── test_auth_attack_detector.py   # Test suite
│   └── config_template.json           # Configurable thresholds
└── README.md
```

## Quick Start

```bash
# Run with demo data
python scripts/auth_attack_detector.py --demo

# Run tests
python scripts/test_auth_attack_detector.py

# Analyze real logs
python scripts/auth_attack_detector.py --input security.evtx --output-json report.json
```

## MITRE ATT&CK Coverage

| Technique | ID | Status |
|-----------|-----|--------|
| Brute Force: Password Guessing | T1110.001 | ✅ Implemented |
| Brute Force: Password Spraying | T1110.003 | ✅ Implemented |
| Brute Force: Credential Stuffing | T1110.004 | ✅ Implemented |
| Privilege Escalation | T1078 / T1098 | 🔲 Planned |
| PowerShell Abuse | T1059.001 | 🔲 Planned |
