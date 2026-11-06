# ==============================================================================
# Product:       lh-log-sentry (lh-sentry)
# Module:        src.lh_log_sentry.rules.ssh_bruteforce
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""SSH brute-force velocity detection rule with sliding time-window."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from lh_log_sentry.models import Anomaly, ParsedLogEntry, Severity
from lh_log_sentry.rules.base import BaseRule


class SSHBruteForceRule(BaseRule):
    """Detects rapid failed SSH logins from a single IP exceeding threshold within time window."""

    rule_id = "LH-SSH-001"
    rule_name = "SSH Brute-Force Velocity Detection"
    severity = Severity.HIGH

    def evaluate(
        self,
        entries: Sequence[ParsedLogEntry],
        window_seconds: int = 300,
        threshold: int = 5,
    ) -> list[Anomaly]:
        """Detect SSH brute force attempts by evaluating failed logins per IP."""
        anomalies: list[Anomaly] = []

        # Filter only failed SSH logins with valid IP and sort by timestamp
        ssh_failures = [e for e in entries if e.event_type == "ssh_failed_login" and e.source_ip]
        if not ssh_failures:
            return anomalies

        # Group by IP
        by_ip: dict[str, list[ParsedLogEntry]] = defaultdict(list)
        for entry in ssh_failures:
            by_ip[entry.source_ip].append(entry)

        for ip, ip_entries in by_ip.items():
            ip_entries.sort(key=lambda x: x.timestamp)
            n = len(ip_entries)
            if n < threshold:
                continue

            left = 0
            while left <= n - threshold:
                # Find maximum window of entries starting at left where delta <= window_seconds
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
                    users_attempted = sorted({e.user for e in cluster if e.user})
                    line_numbers = [e.line_number for e in cluster]
                    evidence = [e.raw_text.strip() for e in cluster]
                    duration = (cluster[-1].timestamp - cluster[0].timestamp).total_seconds()

                    anomaly = Anomaly(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        description=(
                            f"SSH brute-force velocity anomaly: {count} failed logins from "
                            f"{ip} within {duration:.1f}s (window: {window_seconds}s, threshold: {threshold})"
                        ),
                        timestamp=cluster[-1].timestamp,
                        source_ip=ip,
                        user=users_attempted[0] if len(users_attempted) == 1 else None,
                        line_numbers=line_numbers,
                        evidence=evidence,
                        metadata={
                            "attempt_count": count,
                            "window_seconds": window_seconds,
                            "threshold": threshold,
                            "duration_seconds": duration,
                            "targeted_users": users_attempted,
                        },
                    )
                    anomalies.append(anomaly)
                    # Advance left pointer to right to avoid overlapping alerts for same burst
                    left = right
                else:
                    left += 1

        anomalies.sort(key=lambda a: a.timestamp)
        return anomalies
