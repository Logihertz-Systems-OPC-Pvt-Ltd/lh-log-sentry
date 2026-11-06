# lh-log-sentry

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-log-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-log-sentry/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise siem telemetry & intrusion log analyzer developed by **Logihertz Systems (OPC) Private Limited**.

Parses Linux auth.log, syslog, Nginx/Apache access logs, and JSON audit streams to detect SSH brute-force campaigns, sudo privilege escalations, log tampering/truncation gaps, and suspicious command execution.

---

## Key Features

- **Velocity & Threshold Analysis**: Employs sliding-window rate tracking to identify SSH brute-force login attacks and web credential stuffing bursts.
- **Privilege Escalation Detection**: Audits sudo command logs for unauthorized sudoer commands, root shell escapes, and failed `su` attempts.
- **Off-Hours & Impossible Travel Anomaly**: Flags suspicious logins occurring outside normal operational windows or from geographically distant IPs.
- **Web Attack Pattern Matching**: Detects directory traversal (`../`), SQL injection, and XSS patterns in web access logs.
- **Multi-Format Reporting**: Outputs rich terminal tables, machine-readable JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-SSH-001` | `HIGH` | Rapid SSH authentication failure burst (brute-force velocity anomaly) |
| `LH-AUTH-002` | `CRITICAL` | Unauthorized privilege escalation attempt (sudoers violation, su failure) |
| `LH-AUTH-003` | `HIGH` | Off-hours root login or impossible travel velocity anomaly |
| `LH-WEB-001` | `HIGH` | Directory and path traversal attack pattern in web server logs |
| `LH-WEB-002` | `HIGH` | Web injection attack detected (SQLi, XSS, or OS command injection) |
| `LH-WEB-003` | `HIGH` | Web credential stuffing velocity burst (rapid 401/403 response spike) |
| `LH-LOG-001` | `MEDIUM` | Missing or truncated audit log timestamp entries |
| `LH-LOG-002` | `HIGH` | High-frequency 404 scanning probe targeting sensitive administrative paths |
| `LH-LOG-003` | `MEDIUM` | User-Agent spoofing or known offensive security scanner fingerprint |
| `LH-LOG-004` | `LOW` | Unrecognized log record structure or unparsed syslog facility |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-log-sentry.git
cd lh-log-sentry

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-sentry` (also accessible via `lh-sentry`).

```bash
# Analyze Linux auth.log for SSH brute-force attacks
lh-sentry analyze /var/log/auth.log

# Analyze Nginx web access logs
lh-sentry analyze /var/log/nginx/access.log --format json

# Simulate brute-force telemetry for testing
lh-sentry simulate --scenario brute-force

# Export findings to OASIS SARIF v2.1.0
lh-sentry analyze /var/log/auth.log --format sarif --output sentry.sarif
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
