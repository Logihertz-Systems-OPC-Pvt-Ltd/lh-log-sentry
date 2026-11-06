# ==============================================================================
# Product:       lh-log-sentry (lh-sentry)
# Module:        src.lh_log_sentry.parsers.syslog
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Parser for standard Linux syslog files."""

from __future__ import annotations

import re
from typing import Any

from lh_log_sentry.models import ParsedLogEntry
from lh_log_sentry.parsers.base import BaseParser
from lh_log_sentry.parsers.utils import parse_syslog_timestamp

SYSLOG_LINE_RE = re.compile(
    r"^(?P<hostname>[\w.-]+)\s+(?P<program>[a-zA-Z0-9_\-\./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

# Extract IP address patterns if present in message
IP_EXTRACT_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class SyslogParser(BaseParser):
    """Parser for standard Linux syslog entries."""

    def parse_line(self, line_number: int, line: str) -> ParsedLogEntry | None:
        """Parse a syslog line into a ParsedLogEntry."""
        line_clean = line.strip()
        if not line_clean:
            return None

        dt, remainder = parse_syslog_timestamp(line_clean)
        if dt is None:
            return None

        match = SYSLOG_LINE_RE.match(remainder)
        if match:
            hostname = match.group("hostname")
            program = match.group("program")
            pid = match.group("pid")
            message = match.group("message").strip()
        else:
            hostname = None
            program = "syslog"
            pid = None
            message = remainder.strip()

        # Look for possible IP in message
        ip_match = IP_EXTRACT_RE.search(message)
        source_ip = ip_match.group(0) if ip_match else None

        # Check for user keyword in message (e.g. "user=<user>" or "for user <user>")
        user = None
        user_match = re.search(
            r"(?:user\s*=\s*|for\s+user\s+|user\s+)(?P<user>[a-zA-Z0-9_.-]+)",
            message,
            re.IGNORECASE,
        )
        if user_match:
            user = user_match.group("user")

        details: dict[str, Any] = {
            "hostname": hostname,
            "program": program,
            "pid": pid,
        }

        # Determine event_type
        event_type = "syslog_event"
        if "fail" in message.lower() or "error" in message.lower():
            event_type = "syslog_error"
        elif "warning" in message.lower():
            event_type = "syslog_warning"

        return ParsedLogEntry(
            line_number=line_number,
            raw_text=line,
            timestamp=dt,
            log_type="syslog",
            event_type=event_type,
            source_ip=source_ip,
            user=user,
            message=message,
            details=details,
        )
