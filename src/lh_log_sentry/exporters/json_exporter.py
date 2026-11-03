"""JSON exporter for analysis reports."""

from __future__ import annotations

import json
from pathlib import Path

from lh_log_sentry.models import AnalysisReport


def export_json(report: AnalysisReport, output_path: Path | str | None = None) -> str:
    """Export analysis report as a formatted JSON string and optionally write to file."""
    data = report.to_dict()
    json_str = json.dumps(data, indent=2)

    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json_str + "\n", encoding="utf-8")

    return json_str

