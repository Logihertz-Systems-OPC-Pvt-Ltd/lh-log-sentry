# ==============================================================================
# Product:       lh-log-sentry (lh-sentry)
# Module:        src.lh_log_sentry.rules.engine
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Rule execution engine for correlating and evaluating log entries."""

from __future__ import annotations

from collections.abc import Sequence

from lh_log_sentry.models import Anomaly, LogType, ParsedLogEntry
from lh_log_sentry.rules.base import BaseRule
from lh_log_sentry.rules.off_hours_auth import OffHoursAuthRule
from lh_log_sentry.rules.ssh_bruteforce import SSHBruteForceRule
from lh_log_sentry.rules.sudo_escalation import SudoEscalationRule
from lh_log_sentry.rules.web_rules import (
    WebCredentialStuffingRule,
    WebInjectionRule,
    WebPathTraversalRule,
)


class RulesEngine:
    """Coordinates and executes detection rules across parsed entries."""

    def __init__(self, rules: list[BaseRule] | None = None) -> None:
        self.rules = rules if rules is not None else self._get_default_rules()

    @staticmethod
    def _get_default_rules() -> list[BaseRule]:
        return [
            SSHBruteForceRule(),
            SudoEscalationRule(),
            OffHoursAuthRule(),
            WebPathTraversalRule(),
            WebInjectionRule(),
            WebCredentialStuffingRule(),
        ]

    def evaluate(
        self,
        entries: Sequence[ParsedLogEntry],
        window_seconds: int = 300,
        threshold: int = 5,
        log_type: LogType | str = LogType.AUTO,
    ) -> list[Anomaly]:
        """Run applicable rules against parsed log entries.

        Args:
            entries: List of parsed log entries.
            window_seconds: Sliding time-window in seconds.
            threshold: Burst / velocity threshold.
            log_type: Target log type to select active rules.

        Returns:
            Sorted list of detected anomalies.
        """
        if not entries:
            return []

        resolved_type = LogType(log_type) if isinstance(log_type, str) else log_type
        applicable_rules: list[BaseRule] = []

        for rule in self.rules:
            if resolved_type == LogType.WEB:
                if isinstance(
                    rule, (WebPathTraversalRule, WebInjectionRule, WebCredentialStuffingRule)
                ):
                    applicable_rules.append(rule)
            elif resolved_type == LogType.AUTH:
                if isinstance(rule, (SSHBruteForceRule, SudoEscalationRule, OffHoursAuthRule)):
                    applicable_rules.append(rule)
            else:
                # AUTO or SYSLOG: evaluate all rules
                applicable_rules.append(rule)

        all_anomalies: list[Anomaly] = []
        for rule in applicable_rules:
            detected = rule.evaluate(
                entries=entries,
                window_seconds=window_seconds,
                threshold=threshold,
            )
            all_anomalies.extend(detected)

        # Sort anomalies chronologically by timestamp
        all_anomalies.sort(key=lambda a: a.timestamp)
        return all_anomalies
