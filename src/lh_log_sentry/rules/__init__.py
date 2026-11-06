# ==============================================================================
# Product:       lh-log-sentry (lh-sentry)
# Module:        src.lh_log_sentry.rules.__init__
# Role:          Package Initialization & Public API Declarations
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Anomaly detection rules package."""

from lh_log_sentry.rules.base import BaseRule
from lh_log_sentry.rules.engine import RulesEngine
from lh_log_sentry.rules.off_hours_auth import OffHoursAuthRule
from lh_log_sentry.rules.ssh_bruteforce import SSHBruteForceRule
from lh_log_sentry.rules.sudo_escalation import SudoEscalationRule
from lh_log_sentry.rules.web_rules import (
    WebCredentialStuffingRule,
    WebInjectionRule,
    WebPathTraversalRule,
)

__all__ = [
    "BaseRule",
    "OffHoursAuthRule",
    "RulesEngine",
    "SSHBruteForceRule",
    "SudoEscalationRule",
    "WebCredentialStuffingRule",
    "WebInjectionRule",
    "WebPathTraversalRule",
]
