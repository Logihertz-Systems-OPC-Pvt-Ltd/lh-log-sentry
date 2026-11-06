# Security Rules Reference: lh-log-sentry

An enterprise lightweight log anomaly & velocity detector developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-log-sentry`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-SSH-001` | `HIGH` | Brute Force | Rapid SSH Authentication Failure Burst |
| `LH-AUTH-002` | `CRITICAL` | Privilege Escalation | Unauthorized Privilege Escalation Attempt |
| `LH-AUTH-003` | `HIGH` | Access Anomaly | Off-Hours Login or Impossible Travel Velocity |
| `LH-WEB-001` | `HIGH` | Web Attack | Directory and Path Traversal Attack Pattern in Web Logs |
| `LH-WEB-002` | `HIGH` | Web Attack | Web Injection Attack Detected in Access Logs |
| `LH-WEB-003` | `HIGH` | Brute Force | Web Credential Stuffing Velocity Burst |
| `LH-LOG-001` | `MEDIUM` | Log Integrity | Missing or Truncated Audit Log Timestamp Entries |
| `LH-LOG-002` | `HIGH` | Reconnaissance | High-Frequency 404 Scanning Probe on Sensitive Routes |
| `LH-LOG-003` | `MEDIUM` | Reconnaissance | User-Agent Spoofing or Offensive Scanner Fingerprint |
| `LH-LOG-004` | `LOW` | Telemetry | Unrecognized Log Record Structure in Monitored Facility |

---

## Granular Rule Specifications

### `LH-SSH-001`: Rapid SSH Authentication Failure Burst

- **Severity**: `HIGH`
- **Category**: `Brute Force`
- **Description**: Rapid failed SSH logins from single IP within a sliding evaluation window.
- **Remediation**: Block attacking IP via fail2ban or firewall and enforce SSH key authentication.

---

### `LH-AUTH-002`: Unauthorized Privilege Escalation Attempt

- **Severity**: `CRITICAL`
- **Category**: `Privilege Escalation`
- **Description**: Unauthorized sudo command not allowed, su failure, or shell escape attempt.
- **Remediation**: Audit user permissions in /etc/sudoers and review compromised account activity.

---

### `LH-AUTH-003`: Off-Hours Login or Impossible Travel Velocity

- **Severity**: `HIGH`
- **Category**: `Access Anomaly`
- **Description**: Logins occurring outside normal business hours or from geographically impossible origins.
- **Remediation**: Verify user identity via secondary out-of-band communication and enforce conditional access.

---

### `LH-WEB-001`: Directory and Path Traversal Attack Pattern in Web Logs

- **Severity**: `HIGH`
- **Category**: `Web Attack`
- **Description**: Requests containing ../, %2e%2e%2f, or /etc/passwd path traversal sequences.
- **Remediation**: Enforce strict path validation at the application and WAF reverse proxy layer.

---

### `LH-WEB-002`: Web Injection Attack Detected in Access Logs

- **Severity**: `HIGH`
- **Category**: `Web Attack`
- **Description**: SQL injection (UNION SELECT), XSS (<script>), or command injection patterns in query string.
- **Remediation**: Implement parameterized database queries and validate input at application gateway.

---

### `LH-WEB-003`: Web Credential Stuffing Velocity Burst

- **Severity**: `HIGH`
- **Category**: `Brute Force`
- **Description**: High-frequency 401/403 authorization failures on web login routes within sliding window.
- **Remediation**: Deploy edge rate limiting and challenge-response step-up (Turnstile) on login endpoints.

---

### `LH-LOG-001`: Missing or Truncated Audit Log Timestamp Entries

- **Severity**: `MEDIUM`
- **Category**: `Log Integrity`
- **Description**: Log entries omit standard RFC 3339/5424 timestamps, impairing forensic sequencing.
- **Remediation**: Configure rsyslog/systemd-journald to emit high-precision ISO 8601 timestamps.

---

### `LH-LOG-002`: High-Frequency 404 Scanning Probe on Sensitive Routes

- **Severity**: `HIGH`
- **Category**: `Reconnaissance`
- **Description**: Repeated 404 responses for sensitive paths (/.env, /wp-admin, /actuator) from single origin.
- **Remediation**: Block scanning IP address at perimeter firewall and review exposed path definitions.

---

### `LH-LOG-003`: User-Agent Spoofing or Offensive Scanner Fingerprint

- **Severity**: `MEDIUM`
- **Category**: `Reconnaissance`
- **Description**: Requests from automated security scanners (sqlmap, nikto, nuclei) identified by User-Agent.
- **Remediation**: Drop automated offensive scanner User-Agents at the edge WAF reverse proxy.

---

### `LH-LOG-004`: Unrecognized Log Record Structure in Monitored Facility

- **Severity**: `LOW`
- **Category**: `Telemetry`
- **Description**: Log records deviate from configured format specification, preventing parsing.
- **Remediation**: Align logging application output format with structured JSON or Combined Log Format.

---
