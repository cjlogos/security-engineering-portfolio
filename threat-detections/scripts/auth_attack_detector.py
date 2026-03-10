#!/usr/bin/env python3
"""
Authentication Attack Detector
Threat Detection Library - security-engineering-portfolio/threat-detections

Detects brute force, credential stuffing, and password spraying attacks
by analyzing Windows Security Event Logs (Event ID 4625 - Failed Logons).

Usage:
    python auth_attack_detector.py --input <evtx_or_json_file> [options]
    python auth_attack_detector.py --demo  (run with synthetic data)

Output:
    JSON (default) or CSV detection reports
"""

import argparse
import json
import csv
import sys
import os
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum


# ---------------------------------------------------------------------------
# Constants & Configuration Defaults
# ---------------------------------------------------------------------------

class AttackType(str, Enum):
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"
    PASSWORD_SPRAYING = "password_spraying"


DEFAULT_CONFIG = {
    # Brute Force: N failures on ONE account from limited sources in T minutes
    "brute_force": {
        "failure_threshold": 10,
        "time_window_minutes": 5,
        "max_source_ips": 3,
    },
    # Credential Stuffing: ONE source hitting N distinct accounts in T minutes
    "credential_stuffing": {
        "account_threshold": 10,
        "time_window_minutes": 5,
    },
    # Password Spraying: N distinct accounts fail with few passwords in T minutes
    "password_spraying": {
        "account_threshold": 10,
        "time_window_minutes": 30,
        "max_passwords_per_source": 3,
    },
}

# Windows Security Event ID for failed logon
EVENT_ID_FAILED_LOGON = 4625

# Logon failure sub-status codes (for context in alerts)
SUBSTATUS_CODES = {
    "0xc0000064": "User does not exist",
    "0xc000006a": "Incorrect password",
    "0xc0000072": "Account disabled",
    "0xc0000234": "Account locked out",
    "0xc0000071": "Expired password",
    "0xc0000070": "Workstation restriction",
    "0xc00000dc": "SAM server in wrong state",
    "0xc000006d": "Bad username or authentication info",
    "0xc000006f": "Outside authorized hours",
}


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class FailedLogonEvent:
    """Normalized representation of a failed logon event."""
    timestamp: str                  # ISO 8601
    event_id: int = EVENT_ID_FAILED_LOGON
    account_name: str = ""
    account_domain: str = ""
    source_ip: str = ""
    source_hostname: str = ""
    logon_type: int = 0
    failure_reason: str = ""
    sub_status: str = ""
    process_name: str = ""

    @property
    def ts(self) -> datetime:
        """Parse timestamp to datetime for comparisons."""
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(self.timestamp, fmt)
            except ValueError:
                continue
        raise ValueError(f"Unable to parse timestamp: {self.timestamp}")


@dataclass
class Detection:
    """A single detection / alert raised by the engine."""
    attack_type: str
    severity: str                    # critical, high, medium, low
    confidence: float                # 0.0 – 1.0
    summary: str
    first_seen: str
    last_seen: str
    source_ips: list = field(default_factory=list)
    target_accounts: list = field(default_factory=list)
    event_count: int = 0
    mitre_technique: str = ""
    mitre_id: str = ""
    recommendation: str = ""
    details: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Event Parsing
# ---------------------------------------------------------------------------

def parse_evtx_file(filepath: str) -> list[FailedLogonEvent]:
    """
    Parse a Windows .evtx file and extract Event ID 4625 records.
    Requires the python-evtx library.
    """
    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as evtx_views
        import xml.etree.ElementTree as ET
    except ImportError:
        print("[!] python-evtx not installed. Install with: pip install python-evtx")
        print("    Falling back to JSON input mode.")
        return []

    events = []
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"

    with evtx.Evtx(filepath) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
                system = root.find(f"{ns}System")
                event_id_elem = system.find(f"{ns}EventID")
                if event_id_elem is None or int(event_id_elem.text) != EVENT_ID_FAILED_LOGON:
                    continue

                time_created = system.find(f"{ns}TimeCreated")
                timestamp = time_created.get("SystemTime", "")

                event_data = root.find(f"{ns}EventData")
                data_map = {}
                if event_data is not None:
                    for data in event_data.findall(f"{ns}Data"):
                        name = data.get("Name", "")
                        data_map[name] = data.text or ""

                events.append(FailedLogonEvent(
                    timestamp=timestamp,
                    account_name=data_map.get("TargetUserName", ""),
                    account_domain=data_map.get("TargetDomainName", ""),
                    source_ip=data_map.get("IpAddress", ""),
                    source_hostname=data_map.get("WorkstationName", ""),
                    logon_type=int(data_map.get("LogonType", 0)),
                    failure_reason=data_map.get("FailureReason", ""),
                    sub_status=data_map.get("SubStatus", "").lower(),
                    process_name=data_map.get("ProcessName", ""),
                ))
            except Exception:
                continue

    return events


def parse_json_file(filepath: str) -> list[FailedLogonEvent]:
    """
    Parse a JSON file containing an array of failed logon event objects.
    Expected fields mirror FailedLogonEvent attributes.
    """
    with open(filepath, "r") as f:
        raw = json.load(f)

    records = raw if isinstance(raw, list) else raw.get("events", [])
    events = []
    for r in records:
        events.append(FailedLogonEvent(
            timestamp=r.get("timestamp", r.get("TimeCreated", "")),
            event_id=int(r.get("event_id", r.get("EventID", EVENT_ID_FAILED_LOGON))),
            account_name=r.get("account_name", r.get("TargetUserName", "")),
            account_domain=r.get("account_domain", r.get("TargetDomainName", "")),
            source_ip=r.get("source_ip", r.get("IpAddress", "")),
            source_hostname=r.get("source_hostname", r.get("WorkstationName", "")),
            logon_type=int(r.get("logon_type", r.get("LogonType", 0))),
            failure_reason=r.get("failure_reason", r.get("FailureReason", "")),
            sub_status=r.get("sub_status", r.get("SubStatus", "")).lower(),
            process_name=r.get("process_name", r.get("ProcessName", "")),
        ))
    return events


def load_events(filepath: str) -> list[FailedLogonEvent]:
    """Load events from .evtx or .json file."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".evtx":
        return parse_evtx_file(filepath)
    elif ext == ".json":
        return parse_json_file(filepath)
    else:
        print(f"[!] Unsupported file format: {ext}. Use .evtx or .json")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Detection Engine
# ---------------------------------------------------------------------------

class DetectionEngine:
    """Core detection logic for authentication attacks."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or DEFAULT_CONFIG
        self.detections: list[Detection] = []

    def analyze(self, events: list[FailedLogonEvent]) -> list[Detection]:
        """Run all detection modules against the event set."""
        self.detections = []
        if not events:
            return self.detections

        # Sort events chronologically
        events.sort(key=lambda e: e.ts)

        self._detect_brute_force(events)
        self._detect_credential_stuffing(events)
        self._detect_password_spraying(events)

        # Sort detections by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        self.detections.sort(key=lambda d: severity_order.get(d.severity, 4))
        return self.detections

    # -- Brute Force ---------------------------------------------------------
    def _detect_brute_force(self, events: list[FailedLogonEvent]):
        """
        Many failed logins targeting a SINGLE account from limited sources
        within a short time window.
        """
        cfg = self.config["brute_force"]
        window = timedelta(minutes=cfg["time_window_minutes"])
        threshold = cfg["failure_threshold"]
        max_sources = cfg["max_source_ips"]

        # Group events by target account
        by_account: dict[str, list[FailedLogonEvent]] = defaultdict(list)
        for e in events:
            key = f"{e.account_domain}\\{e.account_name}".lower()
            by_account[key].append(e)

        for account, acct_events in by_account.items():
            # Sliding window analysis
            i = 0
            while i < len(acct_events):
                window_events = []
                j = i
                while j < len(acct_events) and (acct_events[j].ts - acct_events[i].ts) <= window:
                    window_events.append(acct_events[j])
                    j += 1

                source_ips = set(e.source_ip for e in window_events if e.source_ip)

                if len(window_events) >= threshold and len(source_ips) <= max_sources:
                    severity = "critical" if len(window_events) >= threshold * 3 else \
                               "high" if len(window_events) >= threshold * 2 else "medium"
                    confidence = min(1.0, len(window_events) / (threshold * 2))

                    self.detections.append(Detection(
                        attack_type=AttackType.BRUTE_FORCE,
                        severity=severity,
                        confidence=round(confidence, 2),
                        summary=(
                            f"Brute force attack detected against account '{account}': "
                            f"{len(window_events)} failed logins from {len(source_ips)} "
                            f"source(s) within {cfg['time_window_minutes']} minutes."
                        ),
                        first_seen=window_events[0].timestamp,
                        last_seen=window_events[-1].timestamp,
                        source_ips=sorted(source_ips),
                        target_accounts=[account],
                        event_count=len(window_events),
                        mitre_technique="Brute Force",
                        mitre_id="T1110.001",
                        recommendation=(
                            "Immediately lock the targeted account and investigate the "
                            "source IP(s). Review for successful logons following the "
                            "attack window. Consider IP-based blocking."
                        ),
                        details={
                            "sub_statuses": list(set(
                                SUBSTATUS_CODES.get(e.sub_status, e.sub_status)
                                for e in window_events if e.sub_status
                            )),
                            "logon_types": list(set(e.logon_type for e in window_events)),
                        },
                    ))
                    # Skip past this detection window
                    i = j
                else:
                    i += 1

    # -- Credential Stuffing -------------------------------------------------
    def _detect_credential_stuffing(self, events: list[FailedLogonEvent]):
        """
        A SINGLE source IP failing against MANY distinct accounts in rapid
        succession — characteristic of automated credential-pair testing.
        """
        cfg = self.config["credential_stuffing"]
        window = timedelta(minutes=cfg["time_window_minutes"])
        account_threshold = cfg["account_threshold"]

        # Group by source IP
        by_source: dict[str, list[FailedLogonEvent]] = defaultdict(list)
        for e in events:
            if e.source_ip:
                by_source[e.source_ip].append(e)

        for source_ip, src_events in by_source.items():
            i = 0
            while i < len(src_events):
                window_events = []
                j = i
                while j < len(src_events) and (src_events[j].ts - src_events[i].ts) <= window:
                    window_events.append(src_events[j])
                    j += 1

                accounts = set(
                    f"{e.account_domain}\\{e.account_name}".lower()
                    for e in window_events
                )

                if len(accounts) >= account_threshold:
                    # Distinguish from password spraying by checking password diversity
                    # Credential stuffing uses unique passwords per account
                    # (approximated by sub_status variety and high event-to-account ratio)
                    events_per_account = len(window_events) / len(accounts)

                    severity = "critical" if len(accounts) >= account_threshold * 3 else \
                               "high" if len(accounts) >= account_threshold * 2 else "medium"
                    confidence = min(1.0, len(accounts) / (account_threshold * 2))

                    # Boost confidence if roughly 1 attempt per account (classic stuffing)
                    if events_per_account <= 1.5:
                        confidence = min(1.0, confidence + 0.15)

                    self.detections.append(Detection(
                        attack_type=AttackType.CREDENTIAL_STUFFING,
                        severity=severity,
                        confidence=round(confidence, 2),
                        summary=(
                            f"Credential stuffing detected from {source_ip}: "
                            f"{len(accounts)} unique accounts targeted with "
                            f"{len(window_events)} attempts in "
                            f"{cfg['time_window_minutes']} minutes."
                        ),
                        first_seen=window_events[0].timestamp,
                        last_seen=window_events[-1].timestamp,
                        source_ips=[source_ip],
                        target_accounts=sorted(accounts),
                        event_count=len(window_events),
                        mitre_technique="Credential Stuffing",
                        mitre_id="T1110.004",
                        recommendation=(
                            "Block the source IP immediately. Check if any accounts "
                            "had successful logons after the attack. Enforce MFA across "
                            "targeted accounts. Cross-reference credentials against "
                            "known breach databases."
                        ),
                        details={
                            "avg_attempts_per_account": round(events_per_account, 2),
                            "sub_statuses": list(set(
                                SUBSTATUS_CODES.get(e.sub_status, e.sub_status)
                                for e in window_events if e.sub_status
                            )),
                        },
                    ))
                    i = j
                else:
                    i += 1

    # -- Password Spraying ---------------------------------------------------
    def _detect_password_spraying(self, events: list[FailedLogonEvent]):
        """
        A source tries a SMALL number of passwords against MANY accounts,
        staying under lockout thresholds per account.
        """
        cfg = self.config["password_spraying"]
        window = timedelta(minutes=cfg["time_window_minutes"])
        account_threshold = cfg["account_threshold"]
        max_pw_per_source = cfg["max_passwords_per_source"]

        # Group by source IP
        by_source: dict[str, list[FailedLogonEvent]] = defaultdict(list)
        for e in events:
            if e.source_ip:
                by_source[e.source_ip].append(e)

        for source_ip, src_events in by_source.items():
            i = 0
            while i < len(src_events):
                window_events = []
                j = i
                while j < len(src_events) and (src_events[j].ts - src_events[i].ts) <= window:
                    window_events.append(src_events[j])
                    j += 1

                accounts = set(
                    f"{e.account_domain}\\{e.account_name}".lower()
                    for e in window_events
                )

                if len(accounts) >= account_threshold:
                    # Check for low attempts-per-account (spray signature)
                    acct_attempt_counts = defaultdict(int)
                    for e in window_events:
                        key = f"{e.account_domain}\\{e.account_name}".lower()
                        acct_attempt_counts[key] += 1

                    max_per_account = max(acct_attempt_counts.values())
                    avg_per_account = len(window_events) / len(accounts)

                    # Password spraying: very few attempts per account
                    if max_per_account <= max_pw_per_source:
                        severity = "critical" if len(accounts) >= account_threshold * 3 else \
                                   "high" if len(accounts) >= account_threshold * 2 else "medium"
                        confidence = min(1.0, len(accounts) / (account_threshold * 2))

                        # High confidence if attempts per account are uniformly low
                        if avg_per_account <= 2.0:
                            confidence = min(1.0, confidence + 0.2)

                        self.detections.append(Detection(
                            attack_type=AttackType.PASSWORD_SPRAYING,
                            severity=severity,
                            confidence=round(confidence, 2),
                            summary=(
                                f"Password spraying detected from {source_ip}: "
                                f"{len(accounts)} accounts targeted with max "
                                f"{max_per_account} attempt(s) per account over "
                                f"{cfg['time_window_minutes']} minutes."
                            ),
                            first_seen=window_events[0].timestamp,
                            last_seen=window_events[-1].timestamp,
                            source_ips=[source_ip],
                            target_accounts=sorted(accounts),
                            event_count=len(window_events),
                            mitre_technique="Password Spraying",
                            mitre_id="T1110.003",
                            recommendation=(
                                "Block the source IP. Enforce MFA organization-wide. "
                                "Audit targeted accounts for successful logons. Consider "
                                "implementing smart lockout policies that track distributed "
                                "failures across accounts."
                            ),
                            details={
                                "max_attempts_per_account": max_per_account,
                                "avg_attempts_per_account": round(avg_per_account, 2),
                                "attempt_distribution": dict(acct_attempt_counts),
                            },
                        ))
                        i = j
                    else:
                        i += 1
                else:
                    i += 1


# ---------------------------------------------------------------------------
# Demo Data Generator
# ---------------------------------------------------------------------------

def generate_demo_events() -> list[FailedLogonEvent]:
    """Generate synthetic events demonstrating all three attack types."""
    events = []
    base_time = datetime(2025, 3, 9, 8, 0, 0)

    # --- Brute Force: one account hammered from a single IP ----------------
    for i in range(25):
        events.append(FailedLogonEvent(
            timestamp=(base_time + timedelta(seconds=i * 10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            account_name="admin",
            account_domain="CORP",
            source_ip="10.0.50.101",
            source_hostname="WKS-UNKNOWN",
            logon_type=3,
            sub_status="0xc000006a",
        ))

    # --- Credential Stuffing: one IP, many accounts, ~1 attempt each -------
    usernames = [f"user{n}" for n in range(1, 21)]
    stuff_base = base_time + timedelta(hours=1)
    for i, user in enumerate(usernames):
        events.append(FailedLogonEvent(
            timestamp=(stuff_base + timedelta(seconds=i * 8)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            account_name=user,
            account_domain="CORP",
            source_ip="198.51.100.47",
            source_hostname="",
            logon_type=10,
            sub_status="0xc000006a",
        ))

    # --- Password Spraying: one IP, many accounts, ≤ 2 attempts each ------
    spray_base = base_time + timedelta(hours=2)
    spray_accounts = [f"employee{n}" for n in range(1, 16)]
    idx = 0
    for acct in spray_accounts:
        for attempt in range(2):
            events.append(FailedLogonEvent(
                timestamp=(spray_base + timedelta(seconds=idx * 12)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                account_name=acct,
                account_domain="CORP",
                source_ip="203.0.113.88",
                source_hostname="",
                logon_type=3,
                sub_status="0xc000006a",
            ))
            idx += 1

    # --- Normal noise: scattered failures (should NOT trigger alerts) ------
    noise_base = base_time + timedelta(hours=3)
    for i in range(5):
        events.append(FailedLogonEvent(
            timestamp=(noise_base + timedelta(minutes=i * 15)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            account_name=f"legit_user{i}",
            account_domain="CORP",
            source_ip=f"10.0.1.{10 + i}",
            source_hostname=f"WKS-{100 + i}",
            logon_type=2,
            sub_status="0xc000006a",
        ))

    return events


# ---------------------------------------------------------------------------
# Output Formatters
# ---------------------------------------------------------------------------

def output_json(detections: list[Detection], filepath: Optional[str] = None):
    """Write detections as JSON."""
    report = {
        "report_generated": datetime.now(tz=None).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_detections": len(detections),
        "severity_summary": {
            "critical": sum(1 for d in detections if d.severity == "critical"),
            "high": sum(1 for d in detections if d.severity == "high"),
            "medium": sum(1 for d in detections if d.severity == "medium"),
            "low": sum(1 for d in detections if d.severity == "low"),
        },
        "detections": [asdict(d) for d in detections],
    }
    output = json.dumps(report, indent=2)
    if filepath:
        with open(filepath, "w") as f:
            f.write(output)
        print(f"[+] JSON report written to {filepath}")
    else:
        print(output)


def output_csv(detections: list[Detection], filepath: str):
    """Write detections as a flat CSV file."""
    fieldnames = [
        "attack_type", "severity", "confidence", "summary",
        "first_seen", "last_seen", "source_ips", "target_accounts",
        "event_count", "mitre_technique", "mitre_id", "recommendation",
    ]
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for d in detections:
            row = asdict(d)
            row["source_ips"] = "; ".join(row["source_ips"])
            row["target_accounts"] = "; ".join(row["target_accounts"])
            row.pop("details", None)
            writer.writerow(row)
    print(f"[+] CSV report written to {filepath}")


def print_summary(detections: list[Detection]):
    """Print a human-readable summary to stdout."""
    print("\n" + "=" * 70)
    print("  AUTHENTICATION ATTACK DETECTION REPORT")
    print("=" * 70)
    print(f"  Generated : {datetime.now(tz=None).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Detections: {len(detections)}")
    print("-" * 70)

    if not detections:
        print("  No authentication attacks detected.")
        print("=" * 70 + "\n")
        return

    severity_colors = {
        "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"
    }

    for i, d in enumerate(detections, 1):
        icon = severity_colors.get(d.severity, "⚪")
        print(f"\n  {icon}  Detection #{i}  [{d.severity.upper()}]  "
              f"(confidence: {d.confidence:.0%})")
        print(f"  Type       : {d.attack_type}")
        print(f"  MITRE      : {d.mitre_technique} ({d.mitre_id})")
        print(f"  Summary    : {d.summary}")
        print(f"  Time Range : {d.first_seen}  →  {d.last_seen}")
        print(f"  Source IPs : {', '.join(d.source_ips)}")
        print(f"  Targets    : {len(d.target_accounts)} account(s)")
        print(f"  Events     : {d.event_count}")
        print(f"  Action     : {d.recommendation}")
        print("-" * 70)

    print("=" * 70 + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Detect brute force, credential stuffing, and password "
                    "spraying attacks in Windows Security Event Logs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --demo
  %(prog)s --input security.evtx --output-json report.json
  %(prog)s --input events.json --output-csv report.csv --output-json report.json
  %(prog)s --input security.evtx --config thresholds.json
        """,
    )
    parser.add_argument("--input", "-i",
                        help="Path to .evtx or .json log file")
    parser.add_argument("--demo", action="store_true",
                        help="Run with synthetic demo data")
    parser.add_argument("--output-json", "-oj",
                        help="Write JSON report to file")
    parser.add_argument("--output-csv", "-oc",
                        help="Write CSV report to file")
    parser.add_argument("--config", "-c",
                        help="Path to JSON config file with custom thresholds")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress console summary output")
    return parser


def load_config(filepath: str) -> dict:
    """Load and merge custom config with defaults."""
    with open(filepath, "r") as f:
        custom = json.load(f)
    merged = {**DEFAULT_CONFIG}
    for key in merged:
        if key in custom:
            merged[key] = {**merged[key], **custom[key]}
    return merged


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.input and not args.demo:
        parser.print_help()
        print("\n[!] Provide --input <file> or --demo to run.")
        sys.exit(1)

    # Load config
    config = DEFAULT_CONFIG
    if args.config:
        config = load_config(args.config)
        print(f"[+] Loaded custom config from {args.config}")

    # Load events
    if args.demo:
        print("[+] Running in demo mode with synthetic event data...")
        events = generate_demo_events()
    else:
        print(f"[+] Loading events from {args.input}...")
        events = load_events(args.input)

    print(f"[+] Loaded {len(events)} failed logon events")

    # Run detection
    engine = DetectionEngine(config)
    detections = engine.analyze(events)
    print(f"[+] Analysis complete: {len(detections)} detection(s)")

    # Output
    if not args.quiet:
        print_summary(detections)

    if args.output_json:
        output_json(detections, args.output_json)

    if args.output_csv:
        output_csv(detections, args.output_csv)

    # Default: print JSON to stdout if no file outputs specified
    if not args.output_json and not args.output_csv and args.quiet:
        output_json(detections)

    return 0 if not detections else len(detections)


if __name__ == "__main__":
    sys.exit(main())
