"""Unit tests for report exporters (Table, JSON, SARIF)."""

import json
from datetime import datetime
from pathlib import Path

from lh_log_sentry.exporters.json_exporter import export_json
from lh_log_sentry.exporters.sarif_exporter import export_sarif
from lh_log_sentry.exporters.table import render_table_report
from lh_log_sentry.models import AnalysisReport, Anomaly, Severity


def create_sample_report() -> AnalysisReport:
    anomaly = Anomaly(
        rule_id="LH-SSH-001",
        rule_name="SSH Brute-Force Velocity Detection",
        severity=Severity.HIGH,
        description="SSH brute-force attack: 5 failed attempts from 198.51.100.1",
        timestamp=datetime(2026, 11, 3, 10, 0, 0),
        source_ip="198.51.100.1",
        user="root",
        line_numbers=[1, 2, 3, 4, 5],
        evidence=["Failed password for root", "Failed password for root"],
        metadata={"attempt_count": 5},
    )
    return AnalysisReport(
        target_file="/var/log/auth.log",
        total_lines=10,
        parsed_lines=10,
        failed_lines=0,
        log_type="auth",
        window_seconds=300,
        threshold=5,
        anomalies=[anomaly],
    )


def test_table_exporter(tmp_path: Path) -> None:
    report = create_sample_report()
    out_file = tmp_path / "table.txt"
    text = render_table_report(report, output_path=out_file)
    assert "LH-SSH-001" in text
    assert "198.51.100.1" in text
    assert out_file.exists()


def test_json_exporter(tmp_path: Path) -> None:
    report = create_sample_report()
    out_file = tmp_path / "report.json"
    raw_json = export_json(report, output_path=out_file)
    data = json.loads(raw_json)
    assert data["report_metadata"]["target_file"] == "/var/log/auth.log"
    assert data["report_metadata"]["anomaly_count"] == 1
    assert data["anomalies"][0]["rule_id"] == "LH-SSH-001"
    assert out_file.exists()


def test_sarif_exporter(tmp_path: Path) -> None:
    report = create_sample_report()
    out_file = tmp_path / "report.sarif"
    raw_sarif = export_sarif(report, output_path=out_file)
    sarif = json.loads(raw_sarif)
    assert sarif["version"] == "2.1.0"
    assert (
        sarif["$schema"]
        == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    )
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "lh-log-sentry"
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "LH-SSH-001"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    assert out_file.exists()
