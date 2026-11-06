# ==============================================================================
# Product:       lh-log-sentry (lh-sentry)
# Module:        src.lh_log_sentry.parsers.base
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

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
