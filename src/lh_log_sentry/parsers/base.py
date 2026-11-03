"""Base parser interface for log processors."""

from __future__ import annotations

from abc import ABC, abstractmethod

from lh_log_sentry.models import ParsedLogEntry


class BaseParser(ABC):
    """Abstract base class for all log parsers."""

    @abstractmethod
    def parse_line(self, line_number: int, line: str) -> ParsedLogEntry | None:
        """Parse a single line of log into a structured ParsedLogEntry.

        Args:
            line_number: 1-based line index in the source log file.
            line: Raw string text of the log line.

        Returns:
            A ParsedLogEntry if successfully parsed, or None if the line does not match.
        """
        raise NotImplementedError

