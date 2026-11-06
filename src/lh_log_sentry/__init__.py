# ==============================================================================
# Product:       lh-log-sentry (lh-sentry)
# Module:        src.lh_log_sentry.__init__
# Role:          Package Initialization & Public API Declarations
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""lh-log-sentry: Lightweight log anomaly detector by Logihertz Systems OPC Pvt Ltd.

Detects SSH brute-force attacks, unauthorized sudo/privilege escalation,
and web access log anomalies with sliding time-window correlation.
"""

from lh_log_sentry.analyzer import LogAnalyzer
from lh_log_sentry.models import (
    AnalysisReport,
    Anomaly,
    LogType,
    OutputFormat,
    ParsedLogEntry,
    Severity,
    SimulationScenario,
)
from lh_log_sentry.parsers.detector import detect_log_type, get_parser
from lh_log_sentry.rules.engine import RulesEngine
from lh_log_sentry.simulator import generate_scenario

__version__ = "0.1.0"
__author__ = "Logihertz Systems OPC Pvt Ltd"

__all__ = [
    "AnalysisReport",
    "Anomaly",
    "LogAnalyzer",
    "LogType",
    "OutputFormat",
    "ParsedLogEntry",
    "RulesEngine",
    "Severity",
    "SimulationScenario",
    "detect_log_type",
    "generate_scenario",
    "get_parser",
]
