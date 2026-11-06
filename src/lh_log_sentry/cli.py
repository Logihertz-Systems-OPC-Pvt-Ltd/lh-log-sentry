# ==============================================================================
# Product:       lh-log-sentry (lh-sentry)
# Module:        src.lh_log_sentry.cli
# Role:          CLI Interface & Execution Controller
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Command line interface for lh-log-sentry."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from lh_log_sentry import __version__
from lh_log_sentry.analyzer import LogAnalyzer
from lh_log_sentry.exporters.json_exporter import export_json
from lh_log_sentry.exporters.sarif_exporter import export_sarif
from lh_log_sentry.exporters.table import render_table_report
from lh_log_sentry.models import LogType, OutputFormat, SimulationScenario
from lh_log_sentry.simulator import generate_scenario

# --- Exit Code Semantics ---
# Exit Code 0: Audit passed successfully with zero policy violations.
# Exit Code 1: Security findings detected meeting or exceeding failure threshold (--fail-on).
# Exit Code 2: Command execution error, invalid arguments, or unparseable input target.

app = typer.Typer(
    name="lh-sentry",
    help="Lightweight Linux & Web Log Anomaly Detector by Logihertz Systems OPC Pvt Ltd.",
    add_completion=False,
)
console = Console()


def version_callback(value: bool) -> None:
    """Print application version and exit."""
    if value:
        console.print(
            f"[bold cyan]lh-sentry[/bold cyan] version [bold green]{__version__}[/bold green]"
        )
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """lh-sentry: Log anomaly detector and security analyzer."""
    pass


@app.command(name="analyze")
def analyze(
    logfile: Path = typer.Argument(
        ...,
        help="Path to the log file to analyze.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    log_type: LogType = typer.Option(
        LogType.AUTO,
        "--log-type",
        "-t",
        help="Log format parser type (auto, auth, web, syslog).",
        case_sensitive=False,
    ),
    window_seconds: int = typer.Option(
        300,
        "--window-seconds",
        "-w",
        help="Sliding time-window duration in seconds for correlation.",
        min=1,
    ),
    threshold: int = typer.Option(
        5,
        "--threshold",
        help="Count threshold within time-window to trigger anomaly alerts.",
        min=1,
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE,
        "--format",
        "-f",
        help="Output report format (table, json, sarif).",
        case_sensitive=False,
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional file path to write the formatted report.",
    ),
) -> None:
    """Analyze a log file to detect security anomalies and attack patterns."""
    analyzer = LogAnalyzer()
    try:
        report = analyzer.analyze_file(
            file_path=logfile,
            log_type=log_type,
            window_seconds=window_seconds,
            threshold=threshold,
        )
    except Exception as exc:
        console.print(f"[bold red]Error analyzing log file:[/bold red] {exc}", style="red")
        raise typer.Exit(code=1) from exc

    if output_format == OutputFormat.TABLE:
        if output is not None:
            render_table_report(report, output_path=output)
            console.print(f"[green]Report saved successfully to:[/green] {output}")
        else:
            render_table_report(report, console=console)
    elif output_format == OutputFormat.JSON:
        json_output = export_json(report, output_path=output)
        if output is not None:
            console.print(f"[green]JSON report saved to:[/green] {output}")
        else:
            console.print(json_output)
    elif output_format == OutputFormat.SARIF:
        sarif_output = export_sarif(report, output_path=output)
        if output is not None:
            console.print(f"[green]SARIF report saved to:[/green] {output}")
        else:
            console.print(sarif_output)


@app.command(name="simulate")
def simulate(
    scenario: SimulationScenario = typer.Option(
        SimulationScenario.SSH_BRUTEFORCE,
        "--scenario",
        "-s",
        help="Attack scenario to simulate (ssh-bruteforce, sudo-escalation, web-attack).",
        case_sensitive=False,
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Destination path to save the simulated log file.",
    ),
    count: int = typer.Option(
        10,
        "--count",
        "-c",
        help="Number of attack attempts or iterations to generate.",
        min=1,
    ),
) -> None:
    """Simulate realistic security attack scenarios and generate sample log files."""
    try:
        lines = generate_scenario(
            scenario=scenario,
            output_path=output,
            count=count,
        )
        if output is not None:
            console.print(
                f"[bold green]Successfully generated {len(lines)} log lines for scenario '{scenario.value}' at:[/bold green] {output}"
            )
        else:
            for line in lines:
                console.print(line)
    except Exception as exc:
        console.print(f"[bold red]Simulation error:[/bold red] {exc}", style="red")
        raise typer.Exit(code=1) from exc


if __name__ == "__main__":
    app()
