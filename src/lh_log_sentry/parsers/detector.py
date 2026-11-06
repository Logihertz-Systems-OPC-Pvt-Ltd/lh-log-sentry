# ==============================================================================
# Product:       lh-log-sentry (lh-sentry)
# Module:        src.lh_log_sentry.parsers.detector
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Parser detector and factory."""

from __future__ import annotations

from collections.abc import Sequence

from lh_log_sentry.models import LogType
from lh_log_sentry.parsers.auth import AuthLogParser
from lh_log_sentry.parsers.base import BaseParser
from lh_log_sentry.parsers.syslog import SyslogParser
from lh_log_sentry.parsers.web import WebLogParser


def detect_log_type(sample_lines: Sequence[str]) -> LogType:
    """Automatically detect the log type by inspecting sample log lines."""
    auth_parser = AuthLogParser()
    web_parser = WebLogParser()
    syslog_parser = SyslogParser()

    web_score = 0
    auth_score = 0
    syslog_score = 0

    valid_lines = [line.strip() for line in sample_lines if line.strip()][:50]
    if not valid_lines:
        return LogType.AUTH

    for idx, line in enumerate(valid_lines, start=1):
        # Test web parser
        if web_parser.parse_line(idx, line) is not None:
            web_score += 2

        # Test auth parser
        auth_entry = auth_parser.parse_line(idx, line)
        if auth_entry is not None:
            # If it's a specific auth event, give high weight
            if auth_entry.event_type in (
                "ssh_failed_login",
                "ssh_accepted_login",
                "sudo_auth_failure",
                "sudo_command",
                "sudo_unauthorized",
                "su_failure",
                "su_success",
            ):
                auth_score += 4
            else:
                auth_score += 1

        # Test syslog parser
        if syslog_parser.parse_line(idx, line) is not None:
            syslog_score += 1

    if web_score > auth_score and web_score > syslog_score:
        return LogType.WEB
    if auth_score >= syslog_score and auth_score > 0:
        return LogType.AUTH
    if syslog_score > 0:
        return LogType.SYSLOG

    return LogType.AUTH


def get_parser(
    log_type: LogType | str, sample_lines: Sequence[str] | None = None
) -> tuple[BaseParser, LogType]:
    """Return appropriate parser instance and resolved log type."""
    resolved_type: LogType
    resolved_type = LogType(log_type.lower()) if isinstance(log_type, str) else log_type

    if resolved_type == LogType.AUTO:
        resolved_type = detect_log_type(sample_lines) if sample_lines else LogType.AUTH

    if resolved_type == LogType.WEB:
        return WebLogParser(), resolved_type
    elif resolved_type == LogType.SYSLOG:
        return SyslogParser(), resolved_type
    else:
        return AuthLogParser(), resolved_type
