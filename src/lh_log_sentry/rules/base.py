"""Base class for anomaly detection rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

from lh_log_sentry.models import Anomaly, ParsedLogEntry, Severity


class BaseRule(ABC):
    """Abstract base class for log anomaly detection rules."""

    rule_id: str
    rule_name: str
    severity: Severity

    def __init__(self, severity: Severity | None = None) -> None:
        if severity is not None:
            self.severity = severity

    @abstractmethod
    def evaluate(
        self,
        entries: Sequence[ParsedLogEntry],
        window_seconds: int = 300,
        threshold: int = 5,
    ) -> list[Anomaly]:
        """Evaluate a sequence of parsed log entries against the rule.

        Args:
            entries: Sequence of parsed log entries.
            window_seconds: Configurable sliding time-window in seconds.
            threshold: Count threshold to trigger the alert.

        Returns:
            List of detected Anomaly instances.
        """
        raise NotImplementedError
