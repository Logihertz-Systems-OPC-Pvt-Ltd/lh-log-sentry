"""Unit tests for synthetic log generator and simulation scenarios."""

from pathlib import Path

from lh_log_sentry.analyzer import LogAnalyzer
from lh_log_sentry.models import SimulationScenario
from lh_log_sentry.simulator import (
    generate_scenario,
    generate_ssh_bruteforce_logs,
    generate_sudo_escalation_logs,
    generate_web_attack_logs,
)


def test_generate_ssh_bruteforce_logs(tmp_path: Path) -> None:
    lines = generate_ssh_bruteforce_logs(burst_count=8)
    assert len(lines) > 8
    assert any("Failed password" in line for line in lines)

    sample_file = tmp_path / "ssh_sample.log"
    out_lines = generate_scenario(
        SimulationScenario.SSH_BRUTEFORCE, output_path=sample_file, count=6
    )
    assert sample_file.exists()
    assert len(out_lines) == len(sample_file.read_text().splitlines())

    analyzer = LogAnalyzer()
    report = analyzer.analyze_file(sample_file, log_type="auth", threshold=5)
    assert report.total_lines > 0
    assert len(report.anomalies) >= 1
    assert any(a.rule_id == "LH-SSH-001" for a in report.anomalies)


def test_generate_sudo_escalation_logs(tmp_path: Path) -> None:
    lines = generate_sudo_escalation_logs()
    assert len(lines) >= 4
    assert any("user NOT in sudoers" in line for line in lines)

    sample_file = tmp_path / "sudo_sample.log"
    generate_scenario(SimulationScenario.SUDO_ESCALATION, output_path=sample_file)
    assert sample_file.exists()

    analyzer = LogAnalyzer()
    report = analyzer.analyze_file(sample_file, log_type="auth")
    assert report.total_lines > 0
    assert len(report.anomalies) >= 2
    assert any(a.rule_id == "LH-AUTH-002" for a in report.anomalies)


def test_generate_web_attack_logs(tmp_path: Path) -> None:
    lines = generate_web_attack_logs(burst_count=6)
    assert len(lines) >= 10
    assert any("/../../etc/passwd" in line for line in lines)
    assert any("UNION" in line for line in lines)
    assert any("<script>" in line for line in lines)

    sample_file = tmp_path / "web_sample.log"
    generate_scenario("web-attack", output_path=sample_file, count=6)
    assert sample_file.exists()

    analyzer = LogAnalyzer()
    report = analyzer.analyze_file(sample_file, log_type="web", threshold=5)
    assert report.total_lines > 0
    rule_ids = {a.rule_id for a in report.anomalies}
    assert "LH-WEB-001" in rule_ids  # Path traversal
    assert "LH-WEB-002" in rule_ids  # Web Injection (SQLi/XSS)
    assert "LH-WEB-003" in rule_ids  # Credential stuffing
