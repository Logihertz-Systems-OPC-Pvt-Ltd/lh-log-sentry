# ==============================================================================
# Product:       lh-log-sentry (lh-sentry)
# Module:        src.lh_log_sentry.exporters.table
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Rich terminal table exporter for analysis reports."""

from __future__ import annotations

import io
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from lh_log_sentry.models import AnalysisReport, Severity

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


def render_table_report(
    report: AnalysisReport,
    output_path: Path | str | None = None,
    console: Console | None = None,
) -> str:
    """Render analysis report to a Rich table or file."""
    # If writing to a file, capture plain or colored text
    string_io = io.StringIO()
    target_console = (
        console
        if console is not None and output_path is None
        else Console(file=string_io, force_terminal=False, width=120)
    )

    # Summary Panel
    meta = (
        f"[bold]Target File:[/bold] {report.target_file}    "
        f"[bold]Log Type:[/bold] {report.log_type.upper()}    "
        f"[bold]Window:[/bold] {report.window_seconds}s    "
        f"[bold]Threshold:[/bold] {report.threshold}\n"
        f"[bold]Total Lines:[/bold] {report.total_lines}    "
        f"[bold]Parsed Lines:[/bold] {report.parsed_lines}    "
        f"[bold]Anomalies Detected:[/bold] {len(report.anomalies)}"
    )
    target_console.print(
        Panel(meta, title="[bold cyan]lh-log-sentry Security Report[/bold cyan]", expand=False)
    )

    if not report.anomalies:
        target_console.print(
            "[bold green]No security anomalies detected in analyzed logs.[/bold green]"
        )
    else:
        table = Table(title="Detected Security Anomalies", header_style="bold magenta", expand=True)
        table.add_column("Timestamp", style="dim", no_wrap=True)
        table.add_column("Severity", justify="center", no_wrap=True)
        table.add_column("Rule ID", style="bold", no_wrap=True)
        table.add_column("Source / Target")
        table.add_column("Lines", justify="center")
        table.add_column("Description", style="white")

        for anomaly in report.anomalies:
            sev_style = SEVERITY_STYLES.get(anomaly.severity, "white")
            sev_text = f"[{sev_style}]{anomaly.severity.value.upper()}[/{sev_style}]"
            source_info = anomaly.source_ip or anomaly.user or "-"
            lines_str = ",".join(str(ln) for ln in anomaly.line_numbers[:3])
            if len(anomaly.line_numbers) > 3:
                lines_str += f" (+{len(anomaly.line_numbers) - 3})"

            table.add_row(
                anomaly.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                sev_text,
                anomaly.rule_id,
                source_info,
                lines_str,
                anomaly.description,
            )

        target_console.print(table)

    output_str = string_io.getvalue()
    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(output_str, encoding="utf-8")

    return output_str
