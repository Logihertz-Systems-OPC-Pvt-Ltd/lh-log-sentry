"""Data models and enums for lh-log-sentry."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class LogType(StrEnum):
    """Supported log formats."""

    AUTO = "auto"
    AUTH = "auth"
    WEB = "web"
    SYSLOG = "syslog"


class Severity(StrEnum):
    """Security severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OutputFormat(StrEnum):
    """Output report formats."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


class SimulationScenario(StrEnum):
    """Supported attack simulation scenarios."""

    SSH_BRUTEFORCE = "ssh-bruteforce"
    SUDO_ESCALATION = "sudo-escalation"
    WEB_ATTACK = "web-attack"


@dataclass(slots=True)
class ParsedLogEntry:
    """Structured representation of an individual parsed log line."""

    line_number: int
    raw_text: str
    timestamp: datetime
    log_type: str
    event_type: str
    source_ip: str | None = None
    user: str | None = None
    message: str = ""
    status_code: int | None = None
    http_method: str | None = None
    http_path: str | None = None
    http_version: str | None = None
    user_agent: str | None = None
    referer: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Anomaly:
    """Security anomaly detected by an evaluation rule."""

    rule_id: str
    rule_name: str
    severity: Severity
    description: str
    timestamp: datetime
    source_ip: str | None = None
    user: str | None = None
    line_numbers: list[int] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert anomaly instance to dictionary."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "user": self.user,
            "line_numbers": list(self.line_numbers),
            "evidence": list(self.evidence),
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class AnalysisReport:
    """Aggregate analysis report container."""

    target_file: str
    total_lines: int
    parsed_lines: int
    failed_lines: int
    log_type: str
    window_seconds: int
    threshold: int
    anomalies: list[Anomaly] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert analysis report instance to dictionary."""
        return {
            "report_metadata": {
                "generated_at": self.timestamp.isoformat(),
                "target_file": self.target_file,
                "log_type": self.log_type,
                "window_seconds": self.window_seconds,
                "threshold": self.threshold,
                "total_lines": self.total_lines,
                "parsed_lines": self.parsed_lines,
                "failed_lines": self.failed_lines,
                "anomaly_count": len(self.anomalies),
            },
            "anomalies": [anomaly.to_dict() for anomaly in self.anomalies],
        }
