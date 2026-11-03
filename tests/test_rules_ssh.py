"""Unit tests for SSH brute-force velocity detection rule."""

from datetime import datetime, timedelta

from lh_log_sentry.models import ParsedLogEntry, Severity
from lh_log_sentry.rules.ssh_bruteforce import SSHBruteForceRule


def test_ssh_bruteforce_triggers_on_threshold() -> None:
    rule = SSHBruteForceRule()
    base_time = datetime(2026, 11, 3, 12, 0, 0)
    entries: list[ParsedLogEntry] = []

    # Generate 5 failed attempts within 50 seconds from 198.51.100.10
    for i in range(5):
        entries.append(
            ParsedLogEntry(
                line_number=i + 1,
                raw_text=f"Failed password for user{i} from 198.51.100.10",
                timestamp=base_time + timedelta(seconds=i * 10),
                log_type="auth",
                event_type="ssh_failed_login",
                source_ip="198.51.100.10",
                user=f"user{i}",
            )
        )

    anomalies = rule.evaluate(entries, window_seconds=300, threshold=5)
    assert len(anomalies) == 1
    anomaly = anomalies[0]
    assert anomaly.rule_id == "LH-SSH-001"
    assert anomaly.severity == Severity.HIGH
    assert anomaly.source_ip == "198.51.100.10"
    assert anomaly.metadata["attempt_count"] == 5
    assert len(anomaly.line_numbers) == 5


def test_ssh_bruteforce_does_not_trigger_below_threshold() -> None:
    rule = SSHBruteForceRule()
    base_time = datetime(2026, 11, 3, 12, 0, 0)
    entries: list[ParsedLogEntry] = []

    for i in range(4):
        entries.append(
            ParsedLogEntry(
                line_number=i + 1,
                raw_text="failed",
                timestamp=base_time + timedelta(seconds=i * 10),
                log_type="auth",
                event_type="ssh_failed_login",
                source_ip="198.51.100.10",
                user="root",
            )
        )

    anomalies = rule.evaluate(entries, window_seconds=300, threshold=5)
    assert len(anomalies) == 0


def test_ssh_bruteforce_window_expiration() -> None:
    rule = SSHBruteForceRule()
    base_time = datetime(2026, 11, 3, 12, 0, 0)
    entries: list[ParsedLogEntry] = []

    # 5 attempts spaced 100 seconds apart (total span 400s > 300s window)
    for i in range(5):
        entries.append(
            ParsedLogEntry(
                line_number=i + 1,
                raw_text="failed",
                timestamp=base_time + timedelta(seconds=i * 100),
                log_type="auth",
                event_type="ssh_failed_login",
                source_ip="198.51.100.10",
                user="root",
            )
        )

    # Within any 300s window, at most 3 or 4 attempts happen, not 5
    anomalies = rule.evaluate(entries, window_seconds=300, threshold=5)
    assert len(anomalies) == 0


def test_ssh_bruteforce_multiple_ips() -> None:
    rule = SSHBruteForceRule()
    base_time = datetime(2026, 11, 3, 12, 0, 0)
    entries: list[ParsedLogEntry] = []

    # Attacker 1: 5 attempts
    for i in range(5):
        entries.append(
            ParsedLogEntry(
                line_number=i + 1,
                raw_text="failed",
                timestamp=base_time + timedelta(seconds=i * 2),
                log_type="auth",
                event_type="ssh_failed_login",
                source_ip="198.51.100.1",
                user="root",
            )
        )

    # Attacker 2: 5 attempts
    for i in range(5):
        entries.append(
            ParsedLogEntry(
                line_number=i + 6,
                raw_text="failed",
                timestamp=base_time + timedelta(seconds=i * 2),
                log_type="auth",
                event_type="ssh_failed_login",
                source_ip="198.51.100.2",
                user="admin",
            )
        )

    anomalies = rule.evaluate(entries, window_seconds=300, threshold=5)
    assert len(anomalies) == 2
    ips = {a.source_ip for a in anomalies}
    assert ips == {"198.51.100.1", "198.51.100.2"}

