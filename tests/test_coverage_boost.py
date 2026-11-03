"""Additional edge-case tests to achieve comprehensive test coverage."""

from datetime import datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lh_log_sentry.analyzer import LogAnalyzer
from lh_log_sentry.cli import app
from lh_log_sentry.exporters.table import render_table_report
from lh_log_sentry.models import AnalysisReport, LogType, Severity, SimulationScenario
from lh_log_sentry.parsers.auth import AuthLogParser
from lh_log_sentry.parsers.syslog import SyslogParser
from lh_log_sentry.parsers.utils import parse_syslog_timestamp, parse_web_timestamp
from lh_log_sentry.parsers.web import WebLogParser
from lh_log_sentry.rules.base import BaseRule
from lh_log_sentry.rules.engine import RulesEngine
from lh_log_sentry.rules.web_rules import WebInjectionRule
from lh_log_sentry.simulator import generate_scenario

runner = CliRunner()


def test_analyzer_file_not_found() -> None:
    analyzer = LogAnalyzer()
    with pytest.raises(FileNotFoundError):
        analyzer.analyze_file("/definitely/nonexistent/file.log")


def test_auth_parser_edge_cases() -> None:
    parser = AuthLogParser()

    # PAM failure with rhost
    line_pam = "Nov  3 10:00:00 host sshd[123]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.99  user=root"
    entry_pam = parser.parse_line(1, line_pam)
    assert entry_pam is not None
    assert entry_pam.source_ip == "192.168.1.99"
    assert entry_pam.user == "root"

    # Sudo command not allowed
    line_denied = "Nov  3 10:00:01 host sudo[124]:    alice : command not allowed ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/reboot"
    entry_denied = parser.parse_line(2, line_denied)
    assert entry_denied is not None
    assert entry_denied.event_type == "sudo_unauthorized"

    # Sudo 3 incorrect attempts direct
    line_att = "Nov  3 10:00:02 host sudo[125]:    alice : 3 incorrect password attempts"
    entry_att = parser.parse_line(3, line_att)
    assert entry_att is not None
    assert entry_att.event_type == "sudo_auth_failure"

    # Sudo user not in sudoers direct
    line_not = "Nov  3 10:00:03 host sudo[126]:    mallory : user NOT in sudoers"
    entry_not = parser.parse_line(4, line_not)
    assert entry_not is not None
    assert entry_not.event_type == "sudo_unauthorized"

    # Su success
    line_su = "Nov  3 10:00:04 host su[127]: Successful su for root by alice"
    entry_su = parser.parse_line(5, line_su)
    assert entry_su is not None
    assert entry_su.event_type == "su_success"
    assert entry_su.user == "alice"
    assert entry_su.details["target_user"] == "root"

    # Line without hostname/service
    line_raw = "Nov  3 10:00:05 Simple message without service tag"
    entry_raw = parser.parse_line(6, line_raw)
    assert entry_raw is not None
    assert entry_raw.event_type == "auth_generic"


def test_web_parser_edge_cases() -> None:
    parser = WebLogParser()
    # Path with spaces or no HTTP version
    line_no_ver = '1.2.3.4 - - [10/Oct/2026:10:00:00 +0000] "GET /test" 200 100'
    entry_no_ver = parser.parse_line(1, line_no_ver)
    assert entry_no_ver is not None
    assert entry_no_ver.http_method == "GET"
    assert entry_no_ver.http_path == "/test"

    # Single token request
    line_single = '1.2.3.4 - - [10/Oct/2026:10:00:00 +0000] "BADREQUEST" 400 0'
    entry_single = parser.parse_line(2, line_single)
    assert entry_single is not None
    assert entry_single.http_path == "BADREQUEST"


def test_syslog_parser_edge_cases() -> None:
    parser = SyslogParser()
    # Warning message with IP and user
    line = "Nov  3 10:00:00 host kernel: [123.45] user admin warning: connection from 192.168.1.5"
    entry = parser.parse_line(1, line)
    assert entry is not None
    assert entry.event_type == "syslog_warning"
    assert entry.source_ip == "192.168.1.5"
    assert entry.user == "admin"


def test_timestamp_utils_edge_cases() -> None:
    # Invalid BSD timestamp
    dt, rem = parse_syslog_timestamp("Xyz 99 99:99:99 not a date")
    assert dt is None

    # Invalid ISO timestamp
    dt_iso, rem_iso = parse_syslog_timestamp("2026-99-99T99:99:99Z test")
    assert dt_iso is None

    # Invalid Web timestamp
    dt_web = parse_web_timestamp("invalid web timestamp")
    assert dt_web is None

    dt_web_month = parse_web_timestamp("10/Xyz/2026:10:00:00 +0000")
    assert dt_web_month is None


def test_rules_engine_empty_and_syslog() -> None:
    engine = RulesEngine()
    assert engine.evaluate([], log_type=LogType.AUTO) == []

    # Custom rule initialization
    class DummyRule(BaseRule):
        rule_id = "LH-DUMMY"
        rule_name = "Dummy Rule"
        severity = Severity.LOW

        def evaluate(self, entries, window_seconds=300, threshold=5):
            return []

    dummy = DummyRule(severity=Severity.MEDIUM)
    assert dummy.severity == Severity.MEDIUM


def test_web_injection_command_injection() -> None:
    rule = WebInjectionRule()
    entries = [
        # Command injection
        from_raw_path("/cgi-bin/test?cmd=;%20cat%20/etc/passwd"),
        # XSS onerror
        from_raw_path("/search?q=<img src=x onerror=alert(1)>"),
    ]
    anomalies = rule.evaluate(entries)
    assert len(anomalies) == 2


def from_raw_path(path: str):
    import urllib.parse

    from lh_log_sentry.models import ParsedLogEntry

    decoded = urllib.parse.unquote_plus(path)
    return ParsedLogEntry(
        line_number=1,
        raw_text=f'1.2.3.4 - - [10/Oct/2026:10:00:00 +0000] "GET {path} HTTP/1.1" 200 100',
        timestamp=datetime(2026, 10, 10, 10, 0, 0),
        log_type="web",
        event_type="web_request",
        source_ip="1.2.3.4",
        http_path=path,
        message=f"GET {path} HTTP/1.1",
        details={"decoded_path": decoded},
    )


def test_render_table_no_anomalies() -> None:
    report = AnalysisReport(
        target_file="test.log",
        total_lines=5,
        parsed_lines=5,
        failed_lines=0,
        log_type="auth",
        window_seconds=300,
        threshold=5,
        anomalies=[],
    )
    rendered = render_table_report(report)
    assert "No security anomalies detected" in rendered


def test_cli_sarif_stdout(tmp_path: Path) -> None:
    log_file = tmp_path / "web.log"
    generate_scenario(SimulationScenario.WEB_ATTACK, output_path=log_file, count=5)
    res = runner.invoke(app, ["analyze", str(log_file), "--format", "sarif"])
    assert res.exit_code == 0
    assert "$schema" in res.stdout


def test_cli_json_stdout(tmp_path: Path) -> None:
    log_file = tmp_path / "auth.log"
    generate_scenario(SimulationScenario.SSH_BRUTEFORCE, output_path=log_file, count=5)
    res = runner.invoke(app, ["analyze", str(log_file), "--format", "json"])
    assert res.exit_code == 0
    assert "report_metadata" in res.stdout


def test_cli_table_file_output(tmp_path: Path) -> None:
    log_file = tmp_path / "auth.log"
    out_table = tmp_path / "out_table.txt"
    generate_scenario(SimulationScenario.SSH_BRUTEFORCE, output_path=log_file, count=5)
    res = runner.invoke(
        app, ["analyze", str(log_file), "--format", "table", "--output", str(out_table)]
    )
    assert res.exit_code == 0
    assert out_table.exists()
    assert "Report saved successfully" in res.stdout


def test_simulator_invalid_scenario() -> None:
    with pytest.raises(ValueError):
        generate_scenario("unknown-scenario")
