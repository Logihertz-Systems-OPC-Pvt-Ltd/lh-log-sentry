# lh-log-sentry

[![CI](https://github.com/logihertz/lh-log-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/logihertz/lh-log-sentry/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A lightweight Linux and web log anomaly detector built by **Logihertz Systems OPC Pvt Ltd**. `lh-log-sentry` parses authentication logs (`auth.log`, `secure`), syslog, and web access logs (Nginx/Apache) using structured regex extractors and sliding time-window aggregators to detect SSH brute-force attacks, unauthorized privilege escalation, impossible-travel events, and web application attack vectors.

---

## Key Features

- **Multi-Format Log Parsers**:
  - **Linux Auth Logs (`auth.log`, `secure`)**: Parses OpenSSH, PAM modules, `sudo` execution, and `su` privilege escalation events. Supports both traditional BSD syslog timestamps (`Nov  3 08:15:22`) and ISO 8601 timestamps.
  - **Web Access Logs**: Parses Nginx and Apache Common Log Format (CLF) and Combined Log Format, with automatic multi-level URL decoding.
  - **Syslog**: Standard system daemon, cron, kernel, and service messages.
  - **Auto-Detection**: Sniffs sample lines to automatically select the optimal parser.

- **Sliding Time-Window Anomaly Detection Rules**:
  - `LH-SSH-001` (SSH Brute-Force Velocity): Detects rapid failed SSH logins exceeding configurable thresholds within a moving time-window.
  - `LH-AUTH-002` (Privilege Escalation): Flags unauthorized sudo executions (`user NOT in sudoers`, `command not allowed`), repeated sudo password failures, suspicious root shell spawns (`/bin/bash`, `visudo`, `passwd`), and failed `su` attempts to root.
  - `LH-AUTH-003` (Off-Hours & Impossible Travel): Identifies authentications from distinct IP addresses within short time windows (impossible travel) and off-hours privileged root logins.
  - `LH-WEB-001` (Web Path Traversal): Detects directory climbing probes (`../`, `%2e%2e%2f`) and sensitive system file access (`/etc/passwd`, `/etc/shadow`, `.env`, `.git/HEAD`).
  - `LH-WEB-002` (Web Injection Attacks): Detects SQL injection (`UNION SELECT`, `' OR 1=1`, sleep functions), Cross-Site Scripting (XSS), and shell command injection.
  - `LH-WEB-003` (Web Credential Stuffing): Detects bursts of 401/403 unauthorized responses from attacker IPs.

- **Flexible Export Formats**:
  - **Rich Terminal Table**: Color-coded, severity-highlighted summaries and tables in terminal.
  - **Structured JSON**: Machine-readable JSON output with comprehensive metadata.
  - **OASIS SARIF v2.1.0**: Standardized Static Analysis Results Interchange Format for CI/CD and GitHub Code Scanning integration.

- **Synthetic Attack Simulator**:
  - Generates realistic, reproducible synthetic log files for testing and validation across `ssh-bruteforce`, `sudo-escalation`, and `web-attack` scenarios.

---

## Installation

Install using [`uv`](https://docs.astral.sh/uv/):

```bash
# Clone the repository
git clone https://github.com/logihertz/lh-log-sentry.git
cd lh-log-sentry

# Create virtual environment and install with dev dependencies
uv venv
uv pip install -e ".[dev]"
```

---

## CLI Interface (`lh-sentry`)

### 1. Analyze Log Files

```bash
# Automatic log format detection with Rich terminal table output
lh-sentry analyze /var/log/auth.log

# Specify log type, custom time window, and threshold
lh-sentry analyze /var/log/auth.log \
  --log-type auth \
  --window-seconds 300 \
  --threshold 5 \
  --format table

# Export findings to structured JSON
lh-sentry analyze /var/log/nginx/access.log \
  --log-type web \
  --format json \
  --output report.json

# Export findings to OASIS SARIF v2.1.0 for CI/CD
lh-sentry analyze /var/log/syslog \
  --log-type syslog \
  --format sarif \
  --output findings.sarif
```

#### CLI Options for `analyze`

| Option | Flag | Description | Default |
| ------ | ---- | ----------- | ------- |
| `logfile` | | Path to log file to inspect | *(Required)* |
| `--log-type` | `-t` | Log parser type (`auto`, `auth`, `web`, `syslog`) | `auto` |
| `--window-seconds` | `-w` | Duration in seconds of sliding time window | `300` |
| `--threshold` | | Minimum event count within window to trigger alert | `5` |
| `--format` | `-f` | Output report format (`table`, `json`, `sarif`) | `table` |
| `--output` | `-o` | Destination file path to save report | None (stdout) |

---

### 2. Simulate Attack Scenarios

Generate synthetic log samples to validate detection rules and SOC workflows:

```bash
# Simulate an SSH brute-force velocity attack
lh-sentry simulate --scenario ssh-bruteforce --count 10 --output sample-ssh.log

# Simulate unauthorized sudo escalation attempts
lh-sentry simulate --scenario sudo-escalation --output sample-sudo.log

# Simulate web path traversal, SQLi, XSS, and credential stuffing
lh-sentry simulate --scenario web-attack --count 8 --output sample-web.log

# Pipe directly into analyzer
lh-sentry analyze sample-ssh.log --format table
```

#### CLI Options for `simulate`

| Option | Flag | Description | Default |
| ------ | ---- | ----------- | ------- |
| `--scenario` | `-s` | Scenario (`ssh-bruteforce`, `sudo-escalation`, `web-attack`) | `ssh-bruteforce` |
| `--output` | `-o` | Destination path to save the generated log file | None (stdout) |
| `--count` | `-c` | Number of attack attempts or iterations | `10` |

---

## Detection Rules Reference

| Rule ID | Name | Severity | Target Logs | Description |
| ------- | ---- | -------- | ----------- | ----------- |
| `LH-SSH-001` | SSH Brute-Force Velocity | HIGH | `auth.log`, `secure` | Detects rapid failed SSH logins per IP within a sliding time window. |
| `LH-AUTH-002` | Privilege Escalation | CRITICAL / HIGH | `auth.log`, `secure` | Detects unauthorized sudoers, command not allowed, su failures, and shell escapes. |
| `LH-AUTH-003` | Off-Hours & Impossible Travel | HIGH / MEDIUM | `auth.log`, `secure` | Detects same-user logins from distinct IPs in rapid succession or late-night root logins. |
| `LH-WEB-001` | Web Path Traversal | HIGH | Nginx / Apache | Detects `../`, URL-encoded directory traversal, and access to `/etc/passwd`, `.env`, etc. |
| `LH-WEB-002` | Web Injection Attacks | HIGH | Nginx / Apache | Detects SQL injection, Cross-Site Scripting (XSS), and command injection patterns. |
| `LH-WEB-003` | Web Credential Stuffing | HIGH | Nginx / Apache | Detects high-rate 401/403 authorization failures within a sliding time window. |

---

## Development & Testing

Run linting, security analysis, and test suites:

```bash
# Lint with Ruff
uv run ruff check .

# Check formatting
uv run ruff format --check .

# Security scanning with Bandit
uv run bandit -r src/

# Run pytest with code coverage
uv run pytest
```

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Logihertz Systems OPC Pvt Ltd.
