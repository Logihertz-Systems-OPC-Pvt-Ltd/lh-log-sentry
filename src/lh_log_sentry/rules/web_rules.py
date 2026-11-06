# ==============================================================================
# Product:       lh-log-sentry (lh-sentry)
# Module:        src.lh_log_sentry.rules.web_rules
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Web log anomaly detection rules (Path Traversal, Injection, Credential Stuffing)."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence

from lh_log_sentry.models import Anomaly, ParsedLogEntry, Severity
from lh_log_sentry.rules.base import BaseRule

# Path traversal regexes
PATH_TRAVERSAL_RE = re.compile(
    r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e)"
    r"|(?:\b(?:etc/(?:passwd|shadow|hosts)|proc/self|boot\.ini|win\.ini|\.env|\.git/(?:HEAD|config)|wp-config\.php|WEB-INF)\b)",
    re.IGNORECASE,
)

# SQL Injection regexes
SQLI_RE = re.compile(
    r"(?:union\s+(?:all\s+)?select"
    r"|\b(?:or|and)\b\s+['\"0-9a-zA-Z_-]+\s*=\s*['\"0-9a-zA-Z_-]+"
    r"|\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d+\s*\)"
    r"|waitfor\s+delay\s+['\"][0-9:]+['\"]"
    r"|;\s*drop\s+table"
    r"|information_schema"
    r"|'\s*--)",
    re.IGNORECASE,
)

# XSS regexes
XSS_RE = re.compile(
    r"(?:<script[\s>]"
    r"|javascript\s*:"
    r"|\b(?:onload|onerror|onclick|onmouseover|onfocus)\s*="
    r"|<img\s+[^>]*src\s*=\s*[\"']?x[\"']?"
    r"|\balert\s*\("
    r"|document\.cookie)",
    re.IGNORECASE,
)

# Command Injection regexes
CMD_INJECTION_RE = re.compile(
    r"(?:;|\||&&|\`|\$\()\s*(?:cat\s+/etc/passwd|id\b|whoami\b|uname\b|/bin/sh|/bin/bash)\b",
    re.IGNORECASE,
)


class WebPathTraversalRule(BaseRule):
    """Detects path traversal and sensitive file access attempts in web logs."""

    rule_id = "LH-WEB-001"
    rule_name = "Web Path Traversal Detection"
    severity = Severity.HIGH

    def evaluate(
        self,
        entries: Sequence[ParsedLogEntry],
        window_seconds: int = 300,
        threshold: int = 1,
    ) -> list[Anomaly]:
        """Detect directory traversal probes in web request paths."""
        anomalies: list[Anomaly] = []

        web_entries = [e for e in entries if e.log_type == "web"]
        for entry in web_entries:
            raw_path = entry.http_path or ""
            decoded_path = entry.details.get("decoded_path", "")
            match = PATH_TRAVERSAL_RE.search(raw_path) or PATH_TRAVERSAL_RE.search(decoded_path)
            if match:
                matched_pattern = match.group(0)
                anomalies.append(
                    Anomaly(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        description=(
                            f"Path traversal probe detected from {entry.source_ip}: "
                            f"'{raw_path}' (pattern: '{matched_pattern}')"
                        ),
                        timestamp=entry.timestamp,
                        source_ip=entry.source_ip,
                        user=entry.user,
                        line_numbers=[entry.line_number],
                        evidence=[entry.raw_text.strip()],
                        metadata={
                            "category": "path_traversal",
                            "http_path": raw_path,
                            "decoded_path": decoded_path,
                            "matched_pattern": matched_pattern,
                            "http_status": entry.status_code,
                        },
                    )
                )

        anomalies.sort(key=lambda a: a.timestamp)
        return anomalies


class WebInjectionRule(BaseRule):
    """Detects SQL Injection (SQLi), Cross-Site Scripting (XSS), and Command Injection in web requests."""

    rule_id = "LH-WEB-002"
    rule_name = "Web Injection Attack Detection"
    severity = Severity.HIGH

    def evaluate(
        self,
        entries: Sequence[ParsedLogEntry],
        window_seconds: int = 300,
        threshold: int = 1,
    ) -> list[Anomaly]:
        """Detect injection payloads in request paths, query parameters, and user-agents."""
        anomalies: list[Anomaly] = []

        web_entries = [e for e in entries if e.log_type == "web"]
        for entry in web_entries:
            path = entry.http_path or ""
            decoded = entry.details.get("decoded_path", "")
            agent = entry.user_agent or ""
            targets = [path, decoded, agent]

            attack_type = None
            matched_pattern = None

            for target in targets:
                sqli_match = SQLI_RE.search(target)
                if sqli_match:
                    attack_type = "SQL Injection (SQLi)"
                    matched_pattern = sqli_match.group(0)
                    break

                xss_match = XSS_RE.search(target)
                if xss_match:
                    attack_type = "Cross-Site Scripting (XSS)"
                    matched_pattern = xss_match.group(0)
                    break

                cmd_match = CMD_INJECTION_RE.search(target)
                if cmd_match:
                    attack_type = "Command Injection"
                    matched_pattern = cmd_match.group(0)
                    break

            if attack_type and matched_pattern:
                anomalies.append(
                    Anomaly(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        description=(
                            f"{attack_type} payload detected from {entry.source_ip}: "
                            f"pattern '{matched_pattern}' in request '{entry.message}'"
                        ),
                        timestamp=entry.timestamp,
                        source_ip=entry.source_ip,
                        user=entry.user,
                        line_numbers=[entry.line_number],
                        evidence=[entry.raw_text.strip()],
                        metadata={
                            "category": "web_injection",
                            "attack_type": attack_type,
                            "matched_pattern": matched_pattern,
                            "http_path": path,
                            "http_status": entry.status_code,
                        },
                    )
                )

        anomalies.sort(key=lambda a: a.timestamp)
        return anomalies


class WebCredentialStuffingRule(BaseRule):
    """Detects high-rate 401/403 credential stuffing and brute-force bursts."""

    rule_id = "LH-WEB-003"
    rule_name = "Web Credential Stuffing Burst Detection"
    severity = Severity.HIGH

    def evaluate(
        self,
        entries: Sequence[ParsedLogEntry],
        window_seconds: int = 300,
        threshold: int = 5,
    ) -> list[Anomaly]:
        """Detect bursts of 401/403 HTTP responses within a sliding time-window."""
        anomalies: list[Anomaly] = []

        unauthorized_entries = [
            e
            for e in entries
            if e.log_type == "web" and e.status_code in (401, 403) and e.source_ip
        ]
        if not unauthorized_entries:
            return anomalies

        by_ip: dict[str, list[ParsedLogEntry]] = defaultdict(list)
        for entry in unauthorized_entries:
            by_ip[entry.source_ip].append(entry)

        for ip, ip_entries in by_ip.items():
            ip_entries.sort(key=lambda x: x.timestamp)
            n = len(ip_entries)
            if n < threshold:
                continue

            left = 0
            while left <= n - threshold:
                right = left
                start_time = ip_entries[left].timestamp
                while (
                    right < n
                    and (ip_entries[right].timestamp - start_time).total_seconds() <= window_seconds
                ):
                    right += 1

                count = right - left
                if count >= threshold:
                    cluster = ip_entries[left:right]
                    duration = (cluster[-1].timestamp - cluster[0].timestamp).total_seconds()
                    endpoints = sorted({e.http_path for e in cluster if e.http_path})

                    anomalies.append(
                        Anomaly(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            severity=self.severity,
                            description=(
                                f"Web credential stuffing burst: {count} unauthorized (401/403) responses "
                                f"for {ip} within {duration:.1f}s (window: {window_seconds}s, threshold: {threshold})"
                            ),
                            timestamp=cluster[-1].timestamp,
                            source_ip=ip,
                            user=cluster[-1].user,
                            line_numbers=[e.line_number for e in cluster],
                            evidence=[e.raw_text.strip() for e in cluster],
                            metadata={
                                "category": "credential_stuffing",
                                "count": count,
                                "window_seconds": window_seconds,
                                "duration_seconds": duration,
                                "targeted_endpoints": endpoints,
                            },
                        )
                    )
                    left = right
                else:
                    left += 1

        anomalies.sort(key=lambda a: a.timestamp)
        return anomalies
