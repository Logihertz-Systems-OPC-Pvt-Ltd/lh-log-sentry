"""Unit tests for sudo and privilege escalation detection rules."""

from datetime import datetime, timedelta

from lh_log_sentry.models import ParsedLogEntry, Severity
from lh_log_sentry.rules.sudo_escalation import SudoEscalationRule


def test_sudo_unauthorized_detection() -> None:
    rule = SudoEscalationRule()
    entry = ParsedLogEntry(
        line_number=10,
        raw_text="bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash",
        timestamp=datetime(2026, 11, 3, 14, 0, 0),
        log_type="auth",
        event_type="sudo_unauthorized",
        user="bob",
        details={"error": "user NOT in sudoers", "command": "/bin/bash", "target_user": "root"},
    )

    anomalies = rule.evaluate([entry])
    assert len(anomalies) == 1
    a = anomalies[0]
    assert a.rule_id == "LH-AUTH-002"
    assert a.severity == Severity.CRITICAL
    assert a.user == "bob"
    assert "user NOT in sudoers" in a.description


def test_su_failure_detection() -> None:
    rule = SudoEscalationRule()
    entry = ParsedLogEntry(
        line_number=20,
        raw_text="FAILED SU (to root) eve on pts/2",
        timestamp=datetime(2026, 11, 3, 14, 5, 0),
        log_type="auth",
        event_type="su_failure",
        user="eve",
        details={"target_user": "root", "tty": "pts/2"},
    )

    anomalies = rule.evaluate([entry])
    assert len(anomalies) == 1
    a = anomalies[0]
    assert a.severity == Severity.HIGH
    assert a.user == "eve"
    assert "Failed su" in a.description


def test_sudo_incorrect_password_attempts() -> None:
    rule = SudoEscalationRule()
    entry = ParsedLogEntry(
        line_number=30,
        raw_text="mallory : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
        timestamp=datetime(2026, 11, 3, 14, 10, 0),
        log_type="auth",
        event_type="sudo_auth_failure",
        user="mallory",
        details={"attempts": "3"},
    )

    anomalies = rule.evaluate([entry])
    assert any("3 incorrect password attempts" in a.description for a in anomalies)


def test_sudo_suspicious_shell_execution() -> None:
    rule = SudoEscalationRule()
    entry = ParsedLogEntry(
        line_number=40,
        raw_text="charlie : TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
        timestamp=datetime(2026, 11, 3, 14, 15, 0),
        log_type="auth",
        event_type="sudo_command",
        user="charlie",
        details={"target_user": "root", "command": "/bin/bash"},
    )

    anomalies = rule.evaluate([entry])
    assert len(anomalies) == 1
    a = anomalies[0]
    assert a.severity == Severity.HIGH
    assert "Suspicious privileged command" in a.description
    assert a.user == "charlie"


def test_sudo_repeated_auth_failures_sliding_window() -> None:
    rule = SudoEscalationRule()
    base_time = datetime(2026, 11, 3, 14, 20, 0)
    entries: list[ParsedLogEntry] = []

    # 4 distinct sudo auth failure entries for user 'dave' within 60 seconds
    for i in range(4):
        entries.append(
            ParsedLogEntry(
                line_number=50 + i,
                raw_text=f"pam_unix(sudo:auth): authentication failure user=dave #{i}",
                timestamp=base_time + timedelta(seconds=i * 15),
                log_type="auth",
                event_type="sudo_auth_failure",
                user="dave",
                details={},
            )
        )

    anomalies = rule.evaluate(entries, window_seconds=300, threshold=3)
    assert any("repeated authentication failures" in a.description for a in anomalies)

