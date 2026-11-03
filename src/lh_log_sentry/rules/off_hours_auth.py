"""Off-hours and impossible-travel authentication detection rules."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from lh_log_sentry.models import Anomaly, ParsedLogEntry, Severity
from lh_log_sentry.rules.base import BaseRule


class OffHoursAuthRule(BaseRule):
    """Detects off-hours privileged logins and impossible-travel authentication."""

    rule_id = "LH-AUTH-003"
    rule_name = "Off-Hours and Impossible Travel Detection"
    severity = Severity.MEDIUM

    def __init__(
        self,
        severity: Severity | None = None,
        off_hours_start: int = 23,
        off_hours_end: int = 5,
    ) -> None:
        super().__init__(severity)
        self.off_hours_start = off_hours_start
        self.off_hours_end = off_hours_end

    def evaluate(
        self,
        entries: Sequence[ParsedLogEntry],
        window_seconds: int = 300,
        threshold: int = 2,
    ) -> list[Anomaly]:
        """Detect off-hours and impossible-travel authentication anomalies."""
        anomalies: list[Anomaly] = []

        # 1. Detect Impossible-Travel (same user logging in successfully from distinct IPs in short window)
        successful_logins = [
            e
            for e in entries
            if e.event_type in ("ssh_accepted_login", "su_success") and e.user and e.source_ip
        ]
        by_user: dict[str, list[ParsedLogEntry]] = defaultdict(list)
        for entry in successful_logins:
            by_user[entry.user].append(entry)

        for user, user_entries in by_user.items():
            user_entries.sort(key=lambda x: x.timestamp)
            n = len(user_entries)
            if n < 2:
                continue

            for i in range(n - 1):
                e1 = user_entries[i]
                e2 = user_entries[i + 1]
                delta = abs((e2.timestamp - e1.timestamp).total_seconds())
                if delta <= window_seconds and e1.source_ip != e2.source_ip:
                    anomalies.append(
                        Anomaly(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            severity=Severity.HIGH,
                            description=(
                                f"Impossible-travel authentication: user '{user}' logged in from distinct "
                                f"IPs ({e1.source_ip} and {e2.source_ip}) within {delta:.1f}s"
                            ),
                            timestamp=e2.timestamp,
                            source_ip=e2.source_ip,
                            user=user,
                            line_numbers=[e1.line_number, e2.line_number],
                            evidence=[e1.raw_text.strip(), e2.raw_text.strip()],
                            metadata={
                                "category": "impossible_travel",
                                "ip1": e1.source_ip,
                                "ip2": e2.source_ip,
                                "delta_seconds": delta,
                            },
                        )
                    )

        # 2. Detect off-hours privileged logins (SSH accepted for root or admin during night hours)
        for entry in successful_logins:
            hour = entry.timestamp.hour
            is_off_hours = (hour >= self.off_hours_start) or (hour < self.off_hours_end)
            if is_off_hours and entry.user in ("root", "admin", "administrator"):
                anomalies.append(
                    Anomaly(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.MEDIUM,
                        description=(
                            f"Off-hours privileged login: user '{entry.user}' logged in at "
                            f"{entry.timestamp.strftime('%H:%M:%S')} from {entry.source_ip}"
                        ),
                        timestamp=entry.timestamp,
                        source_ip=entry.source_ip,
                        user=entry.user,
                        line_numbers=[entry.line_number],
                        evidence=[entry.raw_text.strip()],
                        metadata={
                            "category": "off_hours_login",
                            "hour": hour,
                        },
                    )
                )

        anomalies.sort(key=lambda a: a.timestamp)
        return anomalies
