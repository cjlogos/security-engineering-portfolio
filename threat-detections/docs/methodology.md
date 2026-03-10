# Detection Methodology

## Overview

This document describes the detection engineering methodology used by the Auth Attack Detector, including the analytical approach, threshold rationale, and guidance for tuning in production environments.

---

## Detection Approach

### Sliding Window Analysis

All three detection modules use a **sliding time window** to identify attack patterns:

1. Events are sorted chronologically
2. Events are grouped by the relevant key (target account for brute force, source IP for stuffing/spraying)
3. A window advances through the group, collecting events within the configured duration
4. When the window contents exceed the threshold, a detection is raised
5. The window advances past the detection to avoid duplicate alerts

This approach is preferred over fixed-interval bucketing because attacks can span bucket boundaries, causing split detections or missed alerts.

### Severity Scoring

Severity is assigned based on event volume relative to the threshold:

| Multiplier | Severity |
|------------|----------|
| ≥ 3× threshold | Critical |
| ≥ 2× threshold | High |
| ≥ 1× threshold | Medium |

### Confidence Scoring

Confidence (0.0–1.0) reflects how strongly the pattern matches the expected attack signature:

- **Base confidence** scales linearly with volume (higher volume = higher confidence)
- **Credential stuffing bonus** (+0.15): Applied when the attempts-per-account ratio is ≤ 1.5, matching the classic one-credential-per-account pattern
- **Password spraying bonus** (+0.20): Applied when the average attempts per account is ≤ 2.0, matching the low-and-slow spray signature

---

## Threshold Rationale

### Brute Force Defaults

| Parameter | Default | Rationale |
|-----------|---------|-----------|
| `failure_threshold: 10` | Most account lockout policies trigger at 5–10 failures. Setting the detection at 10 catches attacks that approach or exceed lockout. |
| `time_window_minutes: 5` | Automated tools generate failures in rapid bursts. A 5-minute window captures typical attack runs while limiting noise from slow, incidental failures. |
| `max_source_ips: 3` | True brute force originates from one or few IPs. Allowing up to 3 accounts for NAT/proxy scenarios while filtering distributed attacks (which present as spraying). |

### Credential Stuffing Defaults

| Parameter | Default | Rationale |
|-----------|---------|-----------|
| `account_threshold: 10` | Stuffing tools iterate through credential lists rapidly. 10 unique accounts from one source within the window is abnormal in most environments. |
| `time_window_minutes: 5` | Stuffing attacks are fast — automated tools test hundreds of pairs per minute. A 5-minute window captures bursts while keeping the detection responsive. |

### Password Spraying Defaults

| Parameter | Default | Rationale |
|-----------|---------|-----------|
| `account_threshold: 10` | Spraying targets breadth. 10 accounts with uniform low-count failures is the signature pattern. |
| `time_window_minutes: 30` | Spraying is deliberately slow to evade lockout. A 30-minute window accommodates attackers who space attempts to stay under the radar. |
| `max_passwords_per_source: 3` | Spraying uses 1–2 passwords (rarely 3). This cap distinguishes spraying from stuffing, where each account gets a unique password. |

---

## Tuning Guidance

### High-Security Environments

For environments with strict security postures (financial, healthcare, government):

```json
{
    "brute_force": {
        "failure_threshold": 5,
        "time_window_minutes": 10,
        "max_source_ips": 2
    },
    "credential_stuffing": {
        "account_threshold": 5,
        "time_window_minutes": 10
    },
    "password_spraying": {
        "account_threshold": 5,
        "time_window_minutes": 60,
        "max_passwords_per_source": 2
    }
}
```

**Tradeoff:** Higher alert volume, more false positives from legitimate password resets and helpdesk activity.

### Large Enterprise / High-Noise Environments

For environments with thousands of users and high authentication volume:

```json
{
    "brute_force": {
        "failure_threshold": 20,
        "time_window_minutes": 3,
        "max_source_ips": 2
    },
    "credential_stuffing": {
        "account_threshold": 20,
        "time_window_minutes": 5
    },
    "password_spraying": {
        "account_threshold": 25,
        "time_window_minutes": 30,
        "max_passwords_per_source": 3
    }
}
```

**Tradeoff:** Fewer false positives, but slower/smaller attacks may go undetected.

### Tuning Process

1. **Baseline first**: Run the script against 7–30 days of historical logs with default thresholds
2. **Review false positives**: Identify detections caused by legitimate activity (password resets, service account rotations, helpdesk testing)
3. **Adjust thresholds**: Raise thresholds if false positive rate exceeds your team's review capacity
4. **Exclude known sources**: If specific IPs (helpdesk, PAM tools) generate expected failures, consider pre-filtering them from the input data
5. **Re-validate**: After tuning, re-run against the same historical data to confirm the change reduces noise without missing known-bad events

---

## Overlap Handling

Some attack patterns can trigger multiple detection types. For example, a credential stuffing attack from a single IP targeting 20 accounts with 1 attempt each will match both:

- **Credential stuffing** (many accounts from one IP)
- **Password spraying** (many accounts, low attempts per account)

This is expected behavior. Analysts should review both detections and use the confidence scores and details to determine the most likely classification:

- **Attempts-per-account ≈ 1.0** → Likely credential stuffing
- **Attempts-per-account = 2–3 uniformly** → Likely password spraying
- **Mix of "user not found" and "bad password"** → Likely credential stuffing (breach list contains stale usernames)

---

## Limitations

- **No password visibility**: Windows Event ID 4625 does not log the attempted password. The script infers patterns from account/IP/timing correlations.
- **Log completeness**: Detection quality depends on complete log ingestion. Gaps in forwarding or retention reduce effectiveness.
- **Distributed attacks**: Attacks routed through botnets or rotating proxies will not cluster by source IP and may evade the current detection logic.
- **Kerberos pre-auth**: Kerberos failures (Event ID 4771) are not currently analyzed. Future versions may incorporate this.
- **Legitimate lockout storms**: Mass password changes, AD migrations, or expired service account passwords can mimic attack patterns.

---

## Future Enhancements

- Correlation with Event ID 4624 (Successful Logon) to detect successful compromises following attacks
- Kerberos pre-authentication failure analysis (Event ID 4771)
- Geo-IP enrichment for source IP risk scoring
- Integration with threat intelligence feeds for known-bad IP matching
- Time-of-day anomaly detection (attacks outside business hours)
