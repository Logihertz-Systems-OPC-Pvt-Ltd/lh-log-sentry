# ==============================================================================
# Product:       lh-log-sentry (lh-sentry)
# Module:        tests.test_rules_web
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for web log attack rules."""

from datetime import datetime, timedelta

from lh_log_sentry.models import ParsedLogEntry, Severity
from lh_log_sentry.rules.web_rules import (
    WebCredentialStuffingRule,
    WebInjectionRule,
    WebPathTraversalRule,
)


def test_web_path_traversal_rule() -> None:
    rule = WebPathTraversalRule()
    entries = [
        ParsedLogEntry(
            line_number=1,
            raw_text='10.0.0.1 - - [10/Oct/2026:12:00:00 +0000] "GET /../../etc/passwd HTTP/1.1" 404 150',
            timestamp=datetime(2026, 10, 10, 12, 0, 0),
            log_type="web",
            event_type="web_request",
            source_ip="10.0.0.1",
            http_path="/../../etc/passwd",
            details={"decoded_path": "/../../etc/passwd"},
        ),
        ParsedLogEntry(
            line_number=2,
            raw_text='10.0.0.2 - - [10/Oct/2026:12:00:01 +0000] "GET /index.php?file=%2e%2e%2f%2e%2e%2fboot.ini HTTP/1.1" 403 150',
            timestamp=datetime(2026, 10, 10, 12, 0, 1),
            log_type="web",
            event_type="web_request",
            source_ip="10.0.0.2",
            http_path="/index.php?file=%2e%2e%2f%2e%2e%2fboot.ini",
            details={"decoded_path": "/index.php?file=../../boot.ini"},
        ),
    ]

    anomalies = rule.evaluate(entries)
    assert len(anomalies) == 2
    assert all(a.rule_id == "LH-WEB-001" for a in anomalies)
    assert all(a.severity == Severity.HIGH for a in anomalies)


def test_web_sqli_and_xss_rule() -> None:
    rule = WebInjectionRule()
    entries = [
        ParsedLogEntry(
            line_number=1,
            raw_text='10.0.0.1 - - [10/Oct/2026:12:00:00 +0000] "GET /items?id=1%20UNION%20SELECT%20null,null HTTP/1.1" 200 500',
            timestamp=datetime(2026, 10, 10, 12, 0, 0),
            log_type="web",
            event_type="web_request",
            source_ip="10.0.0.1",
            http_path="/items?id=1%20UNION%20SELECT%20null,null",
            message="GET /items?id=1%20UNION%20SELECT%20null,null HTTP/1.1",
            details={"decoded_path": "/items?id=1 UNION SELECT null,null"},
        ),
        ParsedLogEntry(
            line_number=2,
            raw_text='10.0.0.2 - - [10/Oct/2026:12:00:01 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 400',
            timestamp=datetime(2026, 10, 10, 12, 0, 1),
            log_type="web",
            event_type="web_request",
            source_ip="10.0.0.2",
            http_path="/search?q=<script>alert(1)</script>",
            message="GET /search?q=<script>alert(1)</script> HTTP/1.1",
            details={"decoded_path": "/search?q=<script>alert(1)</script>"},
        ),
    ]

    anomalies = rule.evaluate(entries)
    assert len(anomalies) == 2
    assert any("SQL Injection" in a.description for a in anomalies)
    assert any("Cross-Site Scripting" in a.description for a in anomalies)


def test_web_credential_stuffing_rule() -> None:
    rule = WebCredentialStuffingRule()
    base_time = datetime(2026, 10, 10, 12, 0, 0)
    entries: list[ParsedLogEntry] = []

    # 6 failed responses (401/403) from 203.0.113.88 within 30 seconds
    for i in range(6):
        entries.append(
            ParsedLogEntry(
                line_number=i + 1,
                raw_text=f"POST /api/login #{i}",
                timestamp=base_time + timedelta(seconds=i * 5),
                log_type="web",
                event_type="web_request",
                source_ip="203.0.113.88",
                http_path="/api/login",
                status_code=401 if i % 2 == 0 else 403,
            )
        )

    anomalies = rule.evaluate(entries, window_seconds=300, threshold=5)
    assert len(anomalies) == 1
    a = anomalies[0]
    assert a.rule_id == "LH-WEB-003"
    assert a.source_ip == "203.0.113.88"
    assert a.metadata["count"] == 6
