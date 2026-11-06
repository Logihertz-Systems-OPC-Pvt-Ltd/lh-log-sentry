# ==============================================================================
# Product:       lh-log-sentry (lh-sentry)
# Module:        src.lh_log_sentry.exporters.sarif_exporter
# Role:          SARIF, JSON & Rich Terminal Table Exporters
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""OASIS SARIF v2.1.0 exporter for security analysis reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lh_log_sentry.models import AnalysisReport, Severity

SARIF_SCHEMA_URL = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"

SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def build_sarif_dict(report: AnalysisReport) -> dict[str, Any]:
    """Construct an OASIS SARIF v2.1.0 compliant dictionary from report."""
    # Collect unique rules
    rules_dict: dict[str, dict[str, Any]] = {}
    for anomaly in report.anomalies:
        if anomaly.rule_id not in rules_dict:
            rules_dict[anomaly.rule_id] = {
                "id": anomaly.rule_id,
                "name": anomaly.rule_name,
                "shortDescription": {"text": anomaly.rule_name},
                "defaultConfiguration": {
                    "level": SEVERITY_TO_SARIF_LEVEL.get(anomaly.severity, "warning")
                },
            }

    results: list[dict[str, Any]] = []
    target_uri = Path(report.target_file).name or report.target_file

    for anomaly in report.anomalies:
        primary_line = anomaly.line_numbers[0] if anomaly.line_numbers else 1
        level = SEVERITY_TO_SARIF_LEVEL.get(anomaly.severity, "warning")

        result: dict[str, Any] = {
            "ruleId": anomaly.rule_id,
            "level": level,
            "message": {"text": anomaly.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": target_uri,
                        },
                        "region": {
                            "startLine": primary_line,
                        },
                    }
                }
            ],
            "properties": {
                "severity": anomaly.severity.value,
                "source_ip": anomaly.source_ip,
                "user": anomaly.user,
                "evidence": anomaly.evidence,
                "all_lines": anomaly.line_numbers,
                "metadata": anomaly.metadata,
            },
        }
        results.append(result)

    sarif: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-log-sentry",
                        "fullName": "Logihertz Log Sentry Anomaly Detector",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-log-sentry",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif


def export_sarif(report: AnalysisReport, output_path: Path | str | None = None) -> str:
    # --- OASIS SARIF v2.1.0 Compliance Exporter ---
    # Serializes audit results into standard SARIF JSON format for native
    # GitHub Code Scanning, GitLab Security Dashboard, and IDE integrations.
    """Export analysis report to OASIS SARIF v2.1.0 format and optionally write to file."""
    data = build_sarif_dict(report)
    sarif_str = json.dumps(data, indent=2)

    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(sarif_str + "\n", encoding="utf-8")

    return sarif_str
