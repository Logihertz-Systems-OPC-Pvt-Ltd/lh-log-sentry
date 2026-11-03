"""Helper functions for log parsing, date parsing, and text extraction."""

from __future__ import annotations

import re
from datetime import UTC, datetime

MONTH_MAP = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

# Regex for syslog traditional header: "Oct 11 14:32:05" or "Nov  3 08:15:22"
SYSLOG_BSD_TIMESTAMP_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
)

# Regex for ISO 8601 timestamps
ISO_TIMESTAMP_RE = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)

# Regex for Apache / Nginx timestamps: "10/Oct/2026:13:55:36 +0000"
WEB_TIMESTAMP_RE = re.compile(
    r"(?P<day>\d{2})/(?P<month>[A-Z][a-z]{2})/(?P<year>\d{4}):(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s*(?P<tz>[+-]\d{4})?"
)


def parse_syslog_timestamp(
    raw: str, default_year: int | None = None
) -> tuple[datetime | None, str]:
    """Parse traditional BSD syslog or ISO8601 timestamp from start of line.

    Returns a tuple of (parsed_datetime, remaining_line_content).
    """
    raw_stripped = raw.strip()

    # Check ISO timestamp first
    iso_match = ISO_TIMESTAMP_RE.match(raw_stripped)
    if iso_match:
        iso_str = iso_match.group("iso").replace(" ", "T")
        try:
            # Handle trailing Z or offsets
            dt = datetime.fromisoformat(iso_str)
            # Normalize to naive UTC for consistent window comparison
            if dt.tzinfo is not None:
                dt = dt.astimezone(UTC).replace(tzinfo=None)
            remaining = raw_stripped[iso_match.end() :].lstrip()
            return dt, remaining
        except ValueError:
            pass

    # Check BSD Syslog timestamp
    bsd_match = SYSLOG_BSD_TIMESTAMP_RE.match(raw_stripped)
    if bsd_match:
        month_str = bsd_match.group("month")
        month = MONTH_MAP.get(month_str)
        if month is not None:
            day = int(bsd_match.group("day"))
            hour = int(bsd_match.group("hour"))
            minute = int(bsd_match.group("minute"))
            second = int(bsd_match.group("second"))
            year = default_year or datetime.now().year
            try:
                dt = datetime(year, month, day, hour, minute, second)
                remaining = raw_stripped[bsd_match.end() :].lstrip()
                return dt, remaining
            except ValueError:
                pass

    return None, raw_stripped


def parse_web_timestamp(raw_date_str: str) -> datetime | None:
    """Parse Apache/Nginx web log timestamp format [10/Oct/2026:13:55:36 +0000]."""
    match = WEB_TIMESTAMP_RE.search(raw_date_str)
    if not match:
        return None

    month_str = match.group("month")
    month = MONTH_MAP.get(month_str)
    if month is None:
        return None

    try:
        dt = datetime(
            year=int(match.group("year")),
            month=month,
            day=int(match.group("day")),
            hour=int(match.group("hour")),
            minute=int(match.group("minute")),
            second=int(match.group("second")),
        )
        return dt
    except ValueError:
        return None
