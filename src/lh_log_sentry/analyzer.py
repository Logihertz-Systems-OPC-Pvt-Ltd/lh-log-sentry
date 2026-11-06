# ==============================================================================
# Product:       lh-log-sentry (lh-sentry)
# Module:        src.lh_log_sentry.analyzer
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Log analyzer orchestrator."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from lh_log_sentry.models import AnalysisReport, LogType, ParsedLogEntry
from lh_log_sentry.parsers.detector import get_parser
from lh_log_sentry.rules.engine import RulesEngine


class LogAnalyzer:
    """Orchestrates log reading, parsing, correlation, and anomaly detection."""

    def __init__(self, rules_engine: RulesEngine | None = None) -> None:
        self.rules_engine = rules_engine or RulesEngine()

    def analyze_lines(
        self,
        lines: Sequence[str],
        target_name: str = "stream",
        log_type: LogType | str = LogType.AUTO,
        window_seconds: int = 300,
        threshold: int = 5,
    ) -> AnalysisReport:
        """Analyze a collection of log lines in-memory."""
        parser, resolved_type = get_parser(log_type, sample_lines=lines[:50])

        parsed_entries: list[ParsedLogEntry] = []
        failed_count = 0

        for idx, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            entry = parser.parse_line(idx, line)
            if entry is not None:
                parsed_entries.append(entry)
            else:
                failed_count += 1

        anomalies = self.rules_engine.evaluate(
            entries=parsed_entries,
            window_seconds=window_seconds,
            threshold=threshold,
            log_type=resolved_type,
        )

        return AnalysisReport(
            target_file=target_name,
            total_lines=len(lines),
            parsed_lines=len(parsed_entries),
            failed_lines=failed_count,
            log_type=resolved_type.value,
            window_seconds=window_seconds,
            threshold=threshold,
            anomalies=anomalies,
        )

    def analyze_file(
        self,
        file_path: Path | str,
        log_type: LogType | str = LogType.AUTO,
        window_seconds: int = 300,
        threshold: int = 5,
    ) -> AnalysisReport:
        """Analyze a log file on disk."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return self.analyze_lines(
            lines=lines,
            target_name=str(path),
            log_type=log_type,
            window_seconds=window_seconds,
            threshold=threshold,
        )
