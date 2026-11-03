"""Unit tests for off-hours and impossible-travel authentication detection."""

from datetime import datetime, timedelta

from lh_log_sentry.models import ParsedLogEntry, Severity
from lh_log_sentry.rules.off_hours_auth import OffHoursAuthRule


def test_impossible_travel_detection() -> None:
    rule = OffHoursAuthRule()
    base_time = datetime(2026, 11, 3, 15, 0, 0)
    entries = [
        ParsedLogEntry(
            line_number=1,
            raw_text="Accepted password for alice from 198.51.100.5",
            timestamp=base_time,
            log_type="auth",
            event_type="ssh_accepted_login",
            source_ip="198.51.100.5",
            user="alice",
        ),
        ParsedLogEntry(
            line_number=2,
            raw_text="Accepted password for alice from 203.0.113.99",
            timestamp=base_time + timedelta(seconds=60),
            log_type="auth",
            event_type="ssh_accepted_login",
            source_ip="203.0.113.99",
            user="alice",
        ),
    ]

    anomalies = rule.evaluate(entries, window_seconds=300)
    assert len(anomalies) == 1
    a = anomalies[0]
    assert a.rule_id == "LH-AUTH-003"
    assert a.severity == Severity.HIGH
    assert "Impossible-travel" in a.description
    assert a.user == "alice"


def test_off_hours_privileged_login() -> None:
    rule = OffHoursAuthRule(off_hours_start=23, off_hours_end=5)
    # Login at 02:30 AM
    entry = ParsedLogEntry(
        line_number=5,
        raw_text="Accepted password for root from 192.168.1.50",
        timestamp=datetime(2026, 11, 3, 2, 30, 0),
        log_type="auth",
        event_type="ssh_accepted_login",
        source_ip="192.168.1.50",
        user="root",
    )

    anomalies = rule.evaluate([entry])
    assert len(anomalies) == 1
    a = anomalies[0]
    assert "Off-hours privileged login" in a.description
    assert a.severity == Severity.MEDIUM

