"""Unit tests for the lh-sentry command line interface."""

from pathlib import Path

from typer.testing import CliRunner

from lh_log_sentry.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "lh-sentry version" in result.stdout


def test_cli_simulate_and_analyze_table(tmp_path: Path) -> None:
    log_file = tmp_path / "simulated_ssh.log"
    # Simulate scenario
    sim_result = runner.invoke(
        app,
        ["simulate", "--scenario", "ssh-bruteforce", "--output", str(log_file), "--count", "8"],
    )
    assert sim_result.exit_code == 0
    assert log_file.exists()

    # Analyze with table format
    ana_result = runner.invoke(
        app,
        ["analyze", str(log_file), "--log-type", "auth", "--threshold", "5", "--format", "table"],
    )
    assert ana_result.exit_code == 0
    assert "LH-SSH-001" in ana_result.stdout


def test_cli_analyze_json_and_sarif_output_files(tmp_path: Path) -> None:
    log_file = tmp_path / "simulated_web.log"
    sim_result = runner.invoke(
        app,
        ["simulate", "--scenario", "web-attack", "--output", str(log_file), "--count", "6"],
    )
    assert sim_result.exit_code == 0

    json_file = tmp_path / "out.json"
    json_result = runner.invoke(
        app,
        ["analyze", str(log_file), "--format", "json", "--output", str(json_file)],
    )
    assert json_result.exit_code == 0
    assert json_file.exists()

    sarif_file = tmp_path / "out.sarif"
    sarif_result = runner.invoke(
        app,
        ["analyze", str(log_file), "--format", "sarif", "--output", str(sarif_file)],
    )
    assert sarif_result.exit_code == 0
    assert sarif_file.exists()


def test_cli_simulate_stdout() -> None:
    sim_result = runner.invoke(
        app,
        ["simulate", "--scenario", "sudo-escalation"],
    )
    assert sim_result.exit_code == 0
    assert "sudo" in sim_result.stdout


def test_cli_analyze_nonexistent_file() -> None:
    res = runner.invoke(app, ["analyze", "/nonexistent/path/to/log.log"])
    assert res.exit_code != 0

