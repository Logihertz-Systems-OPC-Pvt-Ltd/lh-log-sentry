"""Parser for Nginx and Apache web access logs (Common and Combined formats)."""

from __future__ import annotations

import re
import urllib.parse

from lh_log_sentry.models import ParsedLogEntry
from lh_log_sentry.parsers.base import BaseParser
from lh_log_sentry.parsers.utils import parse_web_timestamp

# Regex matching Common and Combined Log Formats
WEB_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

REQUEST_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<version>HTTP/[\d.]+))?$")


class WebLogParser(BaseParser):
    """Parser for Nginx/Apache Combined and Common access logs."""

    def parse_line(self, line_number: int, line: str) -> ParsedLogEntry | None:
        """Parse a web access log line into a ParsedLogEntry."""
        line_clean = line.strip()
        if not line_clean:
            return None

        match = WEB_LOG_RE.match(line_clean)
        if not match:
            return None

        ip = match.group("ip")
        user_raw = match.group("user")
        user = user_raw if user_raw != "-" else None
        time_str = match.group("time")
        dt = parse_web_timestamp(time_str)
        if dt is None:
            return None

        status_code = int(match.group("status"))
        size_str = match.group("size")
        size = int(size_str) if size_str.isdigit() else 0
        raw_request = match.group("request")
        referer_raw = match.group("referer")
        referer = referer_raw if referer_raw and referer_raw != "-" else None
        agent_raw = match.group("agent")
        user_agent = agent_raw if agent_raw and agent_raw != "-" else None

        http_method = None
        http_path = None
        http_version = None

        req_match = REQUEST_RE.match(raw_request)
        if req_match:
            http_method = req_match.group("method")
            http_path = req_match.group("path")
            http_version = req_match.group("version")
        else:
            # Fallback for irregular requests
            parts = raw_request.split()
            if len(parts) >= 2:
                http_method = parts[0]
                http_path = parts[1]
                if len(parts) >= 3:
                    http_version = parts[2]
            elif len(parts) == 1:
                http_path = parts[0]

        # URL decode path to catch obfuscated/encoded attacks
        decoded_path = ""
        if http_path:
            try:
                # Perform double decoding to uncover double-encoded attacks (%252e%252e)
                decoded_once = urllib.parse.unquote_plus(http_path)
                decoded_path = urllib.parse.unquote_plus(decoded_once)
            except Exception:
                decoded_path = http_path

        details = {
            "size": size,
            "raw_request": raw_request,
            "decoded_path": decoded_path,
        }

        return ParsedLogEntry(
            line_number=line_number,
            raw_text=line,
            timestamp=dt,
            log_type="web",
            event_type="web_request",
            source_ip=ip,
            user=user,
            message=raw_request,
            status_code=status_code,
            http_method=http_method,
            http_path=http_path,
            http_version=http_version,
            user_agent=user_agent,
            referer=referer,
            details=details,
        )
