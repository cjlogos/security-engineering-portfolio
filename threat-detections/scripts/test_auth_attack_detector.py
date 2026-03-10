#!/usr/bin/env python3
"""
Auth Attack Detector — Test Suite

Validates detection logic against known attack patterns using synthetic data.
Run this to verify the detector is working correctly after configuration changes.

Usage:
    python test_auth_attack_detector.py
    python test_auth_attack_detector.py -v  (verbose output)
"""

import sys
import os
import json
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auth_attack_detector import (
    FailedLogonEvent, DetectionEngine, AttackType, DEFAULT_CONFIG,
    generate_demo_events
)


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def make_event(ts_offset_seconds, account, source_ip, domain="CORP",
               sub_status="0xc000006a", base_time=None):
    """Helper to create a FailedLogonEvent with offset from base time."""
    if base_time is None:
        base_time = datetime(2025, 6, 1, 12, 0, 0)
    ts = base_time + timedelta(seconds=ts_offset_seconds)
    return FailedLogonEvent(
        timestamp=ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        account_name=account,
        account_domain=domain,
        source_ip=source_ip,
        logon_type=3,
        sub_status=sub_status,
    )


def test_brute_force_detection():
    """Should detect brute force: many failures on one account from one IP."""
    events = [make_event(i * 10, "admin", "10.0.0.1") for i in range(15)]
    engine = DetectionEngine()
    detections = engine.analyze(events)

    bf = [d for d in detections if d.attack_type == AttackType.BRUTE_FORCE]
    assert len(bf) >= 1, f"Expected brute force detection, got {len(bf)}"
    assert bf[0].target_accounts == ["corp\\admin"]
    assert "10.0.0.1" in bf[0].source_ips
    return True


def test_brute_force_below_threshold():
    """Should NOT detect brute force when below threshold."""
    events = [make_event(i * 10, "admin", "10.0.0.1") for i in range(5)]
    engine = DetectionEngine()
    detections = engine.analyze(events)

    bf = [d for d in detections if d.attack_type == AttackType.BRUTE_FORCE]
    assert len(bf) == 0, f"Expected no brute force detection, got {len(bf)}"
    return True


def test_credential_stuffing_detection():
    """Should detect credential stuffing: one IP, many accounts, ~1 attempt each."""
    events = [make_event(i * 5, f"user{i}", "198.51.100.1") for i in range(15)]
    engine = DetectionEngine()
    detections = engine.analyze(events)

    cs = [d for d in detections if d.attack_type == AttackType.CREDENTIAL_STUFFING]
    assert len(cs) >= 1, f"Expected credential stuffing detection, got {len(cs)}"
    assert "198.51.100.1" in cs[0].source_ips
    assert len(cs[0].target_accounts) >= 10
    return True


def test_password_spraying_detection():
    """Should detect password spraying: one IP, many accounts, low attempts per account."""
    events = []
    idx = 0
    for acct_num in range(15):
        for attempt in range(2):  # 2 attempts per account
            events.append(make_event(idx * 10, f"employee{acct_num}", "203.0.113.5"))
            idx += 1

    engine = DetectionEngine()
    detections = engine.analyze(events)

    ps = [d for d in detections if d.attack_type == AttackType.PASSWORD_SPRAYING]
    assert len(ps) >= 1, f"Expected password spraying detection, got {len(ps)}"
    assert "203.0.113.5" in ps[0].source_ips
    return True


def test_normal_traffic_no_alerts():
    """Should NOT alert on scattered, normal-looking failures."""
    events = []
    base = datetime(2025, 6, 1, 8, 0, 0)
    for i in range(5):
        events.append(make_event(
            i * 900,  # 15 minutes apart
            f"legit_user{i}",
            f"10.0.1.{10 + i}",
            base_time=base,
        ))
    engine = DetectionEngine()
    detections = engine.analyze(events)

    assert len(detections) == 0, f"Expected no detections for normal traffic, got {len(detections)}"
    return True


def test_severity_scaling():
    """Critical severity when events >= 3x threshold."""
    events = [make_event(i * 5, "admin", "10.0.0.1") for i in range(35)]
    engine = DetectionEngine()
    detections = engine.analyze(events)

    bf = [d for d in detections if d.attack_type == AttackType.BRUTE_FORCE]
    assert len(bf) >= 1
    assert bf[0].severity == "critical", f"Expected critical severity, got {bf[0].severity}"
    return True


def test_custom_config():
    """Custom thresholds should override defaults."""
    custom = {
        "brute_force": {"failure_threshold": 3, "time_window_minutes": 1, "max_source_ips": 1},
        "credential_stuffing": {"account_threshold": 3, "time_window_minutes": 1},
        "password_spraying": {"account_threshold": 3, "time_window_minutes": 5, "max_passwords_per_source": 2},
    }
    events = [make_event(i * 10, "admin", "10.0.0.1") for i in range(4)]
    engine = DetectionEngine(custom)
    detections = engine.analyze(events)

    bf = [d for d in detections if d.attack_type == AttackType.BRUTE_FORCE]
    assert len(bf) >= 1, "Custom threshold of 3 should trigger on 4 events"
    return True


def test_demo_data_produces_all_types():
    """Demo data should produce all three attack types."""
    events = generate_demo_events()
    engine = DetectionEngine()
    detections = engine.analyze(events)

    types_found = set(d.attack_type for d in detections)
    for expected in [AttackType.BRUTE_FORCE, AttackType.CREDENTIAL_STUFFING, AttackType.PASSWORD_SPRAYING]:
        assert expected in types_found, f"Demo data missing {expected} detection"
    return True


def test_mitre_ids():
    """Detections should include correct MITRE ATT&CK IDs."""
    events = generate_demo_events()
    engine = DetectionEngine()
    detections = engine.analyze(events)

    mitre_map = {
        AttackType.BRUTE_FORCE: "T1110.001",
        AttackType.CREDENTIAL_STUFFING: "T1110.004",
        AttackType.PASSWORD_SPRAYING: "T1110.003",
    }
    for d in detections:
        if d.attack_type in mitre_map:
            assert d.mitre_id == mitre_map[d.attack_type], \
                f"{d.attack_type} should have MITRE ID {mitre_map[d.attack_type]}, got {d.mitre_id}"
    return True


# ---- Runner ----------------------------------------------------------------

TESTS = [
    ("Brute force detection", test_brute_force_detection),
    ("Brute force below threshold", test_brute_force_below_threshold),
    ("Credential stuffing detection", test_credential_stuffing_detection),
    ("Password spraying detection", test_password_spraying_detection),
    ("Normal traffic — no alerts", test_normal_traffic_no_alerts),
    ("Severity scaling to critical", test_severity_scaling),
    ("Custom config thresholds", test_custom_config),
    ("Demo data — all attack types", test_demo_data_produces_all_types),
    ("MITRE ATT&CK IDs", test_mitre_ids),
]


def run_tests(verbose=False):
    passed = 0
    failed = 0
    errors = []

    print(f"\n{Colors.BOLD}Auth Attack Detector — Test Suite{Colors.RESET}")
    print("=" * 50)

    for name, test_fn in TESTS:
        try:
            test_fn()
            passed += 1
            print(f"  {Colors.GREEN}✓{Colors.RESET}  {name}")
        except AssertionError as e:
            failed += 1
            errors.append((name, str(e)))
            print(f"  {Colors.RED}✗{Colors.RESET}  {name}")
            if verbose:
                print(f"     {Colors.RED}{e}{Colors.RESET}")
        except Exception as e:
            failed += 1
            errors.append((name, str(e)))
            print(f"  {Colors.RED}✗{Colors.RESET}  {name} (ERROR)")
            if verbose:
                print(f"     {Colors.RED}{e}{Colors.RESET}")

    print("=" * 50)
    color = Colors.GREEN if failed == 0 else Colors.RED
    print(f"  {color}{passed} passed, {failed} failed{Colors.RESET}\n")

    if errors and not verbose:
        print(f"  Run with {Colors.YELLOW}-v{Colors.RESET} for failure details.\n")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    sys.exit(run_tests(verbose))
