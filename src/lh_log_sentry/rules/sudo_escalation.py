# ==============================================================================
# Product:       lh-log-sentry (lh-sentry)
# Module:        src.lh_log_sentry.rules.sudo_escalation
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Sudo and privilege escalation detection rules."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence

from lh_log_sentry.models import Anomaly, ParsedLogEntry, Severity
from lh_log_sentry.rules.base import BaseRule

# Sensitive / shell spawning commands executed under sudo/su
SUSPICIOUS_COMMAND_RE = re.compile(
    r"(?:^|[\s/])(?:(?:ba)?sh|zsh|su|visudo|passwd|useradd|usermod)\b|\b(?:chmod\s+[0-7]{3,4}|chmod\s+\+s|cat\s+/etc/shadow)\b",
    re.IGNORECASE,
)


class SudoEscalationRule(BaseRule):
    """Detects unauthorized sudo executions, password failures, and suspicious privilege escalation."""

    rule_id = "LH-AUTH-002"
    rule_name = "Privilege Escalation Detection"
    severity = Severity.HIGH

    def evaluate(
        self,
        entries: Sequence[ParsedLogEntry],
        window_seconds: int = 300,
        threshold: int = 3,
    ) -> list[Anomaly]:
        """Detect privilege escalation anomalies in auth entries."""
        anomalies: list[Anomaly] = []

        # 1. Immediate detection of unauthorized sudo access (not in sudoers or command not allowed)
        unauthorized_events = [e for e in entries if e.event_type == "sudo_unauthorized"]
        for entry in unauthorized_events:
            error = entry.details.get("error") or "unauthorized sudo attempt"
            cmd = entry.details.get("command", "")
            anomalies.append(
                Anomaly(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.CRITICAL,
                    description=f"Unauthorized sudo privilege escalation: user '{entry.user}' ({error}) command: {cmd}",
                    timestamp=entry.timestamp,
                    source_ip=entry.source_ip,
                    user=entry.user,
                    line_numbers=[entry.line_number],
                    evidence=[entry.raw_text.strip()],
                    metadata={
                        "category": "unauthorized_sudo",
                        "command": cmd,
                        "target_user": entry.details.get("target_user"),
                        "error": error,
                    },
                )
            )

        # 2. SU failure detections (e.g. FAILED SU to root)
        su_failures = [e for e in entries if e.event_type == "su_failure"]
        for entry in su_failures:
            target = entry.details.get("target_user", "unknown")
            anomalies.append(
                Anomaly(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.HIGH,
                    description=f"Failed su privilege escalation attempt: user '{entry.user}' attempted switch to '{target}'",
                    timestamp=entry.timestamp,
                    source_ip=entry.source_ip,
                    user=entry.user,
                    line_numbers=[entry.line_number],
                    evidence=[entry.raw_text.strip()],
                    metadata={
                        "category": "su_failure",
                        "target_user": target,
                    },
                )
            )

        # 3. Sudo authentication failures with sliding window
        sudo_auth_failures = [e for e in entries if e.event_type == "sudo_auth_failure"]
        by_user: dict[str, list[ParsedLogEntry]] = defaultdict(list)
        for entry in sudo_auth_failures:
            usr = entry.user or "unknown"
            by_user[usr].append(entry)

        for user, user_entries in by_user.items():
            user_entries.sort(key=lambda x: x.timestamp)
            n = len(user_entries)
            # Check individual entries that report explicit multiple attempts (e.g. "3 incorrect password attempts")
            for entry in user_entries:
                if entry.details.get("attempts"):
                    anomalies.append(
                        Anomaly(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            severity=Severity.HIGH,
                            description=f"Sudo authentication failure burst: user '{user}' triggered {entry.details['attempts']} incorrect password attempts",
                            timestamp=entry.timestamp,
                            source_ip=entry.source_ip,
                            user=user,
                            line_numbers=[entry.line_number],
                            evidence=[entry.raw_text.strip()],
                            metadata={
                                "category": "sudo_pwd_attempts",
                                "attempts": entry.details["attempts"],
                            },
                        )
                    )

            # Check sliding window for multiple sudo auth failures
            left = 0
            while left <= n - threshold:
                right = left
                start_time = user_entries[left].timestamp
                while (
                    right < n
                    and (user_entries[right].timestamp - start_time).total_seconds()
                    <= window_seconds
                ):
                    right += 1

                count = right - left
                if count >= threshold:
                    cluster = user_entries[left:right]
                    # Filter out if already alerted above via attempts flag
                    cluster_lines = [
                        e.line_number for e in cluster if not e.details.get("attempts")
                    ]
                    if cluster_lines:
                        anomalies.append(
                            Anomaly(
                                rule_id=self.rule_id,
                                rule_name=self.rule_name,
                                severity=Severity.HIGH,
                                description=(
                                    f"Sudo repeated authentication failures: user '{user}' accumulated {count} "
                                    f"failures within {window_seconds}s"
                                ),
                                timestamp=cluster[-1].timestamp,
                                source_ip=cluster[-1].source_ip,
                                user=user,
                                line_numbers=cluster_lines,
                                evidence=[
                                    e.raw_text.strip()
                                    for e in cluster
                                    if e.line_number in cluster_lines
                                ],
                                metadata={
                                    "category": "sudo_failure_burst",
                                    "failure_count": count,
                                    "window_seconds": window_seconds,
                                },
                            )
                        )
                    left = right
                else:
                    left += 1

        # 4. Sudo execution of high-risk shell spawning or shadow inspection commands
        sudo_commands = [e for e in entries if e.event_type == "sudo_command"]
        for entry in sudo_commands:
            cmd = entry.details.get("command", "")
            if SUSPICIOUS_COMMAND_RE.search(cmd):
                target_user = entry.details.get("target_user", "root")
                anomalies.append(
                    Anomaly(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.HIGH,
                        description=(
                            f"Suspicious privileged command execution via sudo: user '{entry.user}' "
                            f"executed '{cmd}' as '{target_user}'"
                        ),
                        timestamp=entry.timestamp,
                        source_ip=entry.source_ip,
                        user=entry.user,
                        line_numbers=[entry.line_number],
                        evidence=[entry.raw_text.strip()],
                        metadata={
                            "category": "suspicious_sudo_command",
                            "command": cmd,
                            "target_user": target_user,
                        },
                    )
                )

        anomalies.sort(key=lambda a: a.timestamp)
        return anomalies
