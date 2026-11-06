# ==============================================================================
# Product:       lh-log-sentry (lh-sentry)
# Module:        src.lh_log_sentry.parsers.auth
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Parser for Linux authentication logs (OpenSSH, PAM, sudo, su)."""

from __future__ import annotations

import re
from typing import Any

from lh_log_sentry.models import ParsedLogEntry
from lh_log_sentry.parsers.base import BaseParser
from lh_log_sentry.parsers.utils import parse_syslog_timestamp

# Matches hostname and service[pid]: prefix
# e.g., "myhost sshd[1234]: " or "debian sudo: " or "kernel: "
SERVICE_PREFIX_RE = re.compile(
    r"^(?P<hostname>[\w.-]+)\s+(?P<service>[a-zA-Z0-9_\-\./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

# OpenSSH regex patterns
SSH_FAILED_PWD_RE = re.compile(
    r"Failed (?:password|publickey) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F.:]+) port (?P<port>\d+) ssh2"
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>[\da-fA-F.:]+) port (?P<port>\d+) ssh2"
)
SSH_INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\da-fA-F.:]+)(?: port (?P<port>\d+))?"
)
SSH_DISCONNECT_PREAUTH_RE = re.compile(
    r"(?:Connection closed by|Disconnected from) (?:authenticating user )?(?P<user>\S+)?\s*(?P<ip>[\da-fA-F.:]+) port (?P<port>\d+)\s*\[preauth\]"
)

# PAM patterns
PAM_FAILURE_RE = re.compile(
    r"pam_unix\((?P<module>[^)]+)\):\s*authentication failure;\s*(?P<params>.*)$"
)

# Sudo execution patterns
SUDO_EXEC_RE = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*(?:(?P<error>3 incorrect password attempts|user NOT in sudoers|command not allowed)\s*;\s*)?TTY=(?P<tty>\S*)\s*;\s*PWD=(?P<pwd>[^;]*)\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$"
)
SUDO_ATTEMPTS_RE = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*(?P<attempts>\d+)\s+incorrect password attempts"
)
SUDO_NOT_IN_SUDOERS_RE = re.compile(r"^\s*(?P<user>\S+)\s*:\s*user NOT in sudoers")
SUDO_CMD_NOT_ALLOWED_RE = re.compile(r"^\s*(?P<user>\S+)\s*:\s*command not allowed")

# Su patterns
SU_FAILED_RE = re.compile(
    r"FAILED SU \(to (?P<target_user>\S+)\)\s+(?P<user>\S+)\s+on\s+(?P<tty>\S+)"
)
SU_SUCCESS_RE = re.compile(
    r"(?:\(to (?P<target_user>\S+)\)\s+(?P<user>\S+)\s+on\s+(?P<tty>\S+)|Successful su for (?P<target_user2>\S+) by (?P<user2>\S+))"
)


class AuthLogParser(BaseParser):
    """Parser for Linux authentication logs (auth.log, secure)."""

    def parse_line(self, line_number: int, line: str) -> ParsedLogEntry | None:
        """Parse an auth.log line into a ParsedLogEntry."""
        line_clean = line.strip()
        if not line_clean:
            return None

        dt, remainder = parse_syslog_timestamp(line_clean)
        if dt is None:
            return None

        # Parse service prefix
        svc_match = SERVICE_PREFIX_RE.match(remainder)
        if svc_match:
            service = svc_match.group("service")
            msg = svc_match.group("message").strip()
            hostname = svc_match.group("hostname")
            pid = svc_match.group("pid")
        else:
            # Fallback if no hostname/service prefix is found
            service = "auth"
            msg = remainder.strip()
            hostname = None
            pid = None

        details: dict[str, Any] = {
            "service": service,
            "hostname": hostname,
            "pid": pid,
        }

        # 1. Check OpenSSH Failed Login
        ssh_fail = SSH_FAILED_PWD_RE.search(msg)
        if ssh_fail:
            user = ssh_fail.group("user")
            ip = ssh_fail.group("ip")
            port = int(ssh_fail.group("port"))
            is_invalid = bool(ssh_fail.group("invalid"))
            details.update({"port": port, "is_invalid_user": is_invalid})
            return ParsedLogEntry(
                line_number=line_number,
                raw_text=line,
                timestamp=dt,
                log_type="auth",
                event_type="ssh_failed_login",
                source_ip=ip,
                user=user,
                message=msg,
                details=details,
            )

        # 2. Check OpenSSH Accepted Login
        ssh_acc = SSH_ACCEPTED_RE.search(msg)
        if ssh_acc:
            user = ssh_acc.group("user")
            ip = ssh_acc.group("ip")
            method = ssh_acc.group("method")
            port = int(ssh_acc.group("port"))
            details.update({"port": port, "auth_method": method})
            return ParsedLogEntry(
                line_number=line_number,
                raw_text=line,
                timestamp=dt,
                log_type="auth",
                event_type="ssh_accepted_login",
                source_ip=ip,
                user=user,
                message=msg,
                details=details,
            )

        # 3. Check OpenSSH Invalid User
        ssh_inv = SSH_INVALID_USER_RE.search(msg)
        if ssh_inv:
            user = ssh_inv.group("user")
            ip = ssh_inv.group("ip")
            port = int(ssh_inv.group("port")) if ssh_inv.group("port") else None
            details.update({"port": port, "is_invalid_user": True})
            return ParsedLogEntry(
                line_number=line_number,
                raw_text=line,
                timestamp=dt,
                log_type="auth",
                event_type="ssh_failed_login",
                source_ip=ip,
                user=user,
                message=msg,
                details=details,
            )

        # 4. Check OpenSSH disconnect preauth
        ssh_disc = SSH_DISCONNECT_PREAUTH_RE.search(msg)
        if ssh_disc:
            user = ssh_disc.group("user")
            ip = ssh_disc.group("ip")
            port = int(ssh_disc.group("port"))
            details.update({"port": port, "preauth_disconnect": True})
            return ParsedLogEntry(
                line_number=line_number,
                raw_text=line,
                timestamp=dt,
                log_type="auth",
                event_type="ssh_disconnect_preauth",
                source_ip=ip,
                user=user,
                message=msg,
                details=details,
            )

        # 5. Check PAM Failure
        pam_match = PAM_FAILURE_RE.search(msg)
        if pam_match:
            module = pam_match.group("module")
            param_str = pam_match.group("params")
            # Parse key=value pairs in PAM message
            pam_params: dict[str, str] = {}
            for item in re.finditer(r"(?P<k>\w+)=(?P<v>\S*)", param_str):
                pam_params[item.group("k")] = item.group("v")
            user = pam_params.get("user") or pam_params.get("ruser")
            rhost = pam_params.get("rhost") or None
            if rhost and not rhost.strip():
                rhost = None
            details.update({"pam_module": module, "pam_params": pam_params})
            event_type = "sudo_auth_failure" if "sudo" in module else "auth_failure"
            return ParsedLogEntry(
                line_number=line_number,
                raw_text=line,
                timestamp=dt,
                log_type="auth",
                event_type=event_type,
                source_ip=rhost,
                user=user,
                message=msg,
                details=details,
            )

        # 6. Check Sudo Execution / Failure
        sudo_exec = SUDO_EXEC_RE.match(msg)
        if sudo_exec:
            user = sudo_exec.group("user")
            target_user = sudo_exec.group("target_user")
            cmd = sudo_exec.group("cmd")
            tty = sudo_exec.group("tty")
            pwd = sudo_exec.group("pwd")
            error = sudo_exec.group("error")
            details.update(
                {
                    "target_user": target_user,
                    "command": cmd,
                    "tty": tty,
                    "pwd": pwd,
                    "error": error,
                }
            )
            event_type = "sudo_unauthorized" if error else "sudo_command"
            return ParsedLogEntry(
                line_number=line_number,
                raw_text=line,
                timestamp=dt,
                log_type="auth",
                event_type=event_type,
                user=user,
                message=msg,
                details=details,
            )

        # 6b. Other Sudo alerts (incorrect attempts or not in sudoers)
        sudo_att = SUDO_ATTEMPTS_RE.search(msg)
        if sudo_att:
            user = sudo_att.group("user")
            details["attempts"] = sudo_att.group("attempts")
            return ParsedLogEntry(
                line_number=line_number,
                raw_text=line,
                timestamp=dt,
                log_type="auth",
                event_type="sudo_auth_failure",
                user=user,
                message=msg,
                details=details,
            )

        sudo_not = SUDO_NOT_IN_SUDOERS_RE.search(msg)
        if sudo_not:
            user = sudo_not.group("user")
            return ParsedLogEntry(
                line_number=line_number,
                raw_text=line,
                timestamp=dt,
                log_type="auth",
                event_type="sudo_unauthorized",
                user=user,
                message=msg,
                details=details,
            )

        sudo_denied = SUDO_CMD_NOT_ALLOWED_RE.search(msg)
        if sudo_denied:
            user = sudo_denied.group("user")
            return ParsedLogEntry(
                line_number=line_number,
                raw_text=line,
                timestamp=dt,
                log_type="auth",
                event_type="sudo_unauthorized",
                user=user,
                message=msg,
                details=details,
            )

        # 7. Check Su Failure / Success
        su_fail = SU_FAILED_RE.search(msg)
        if su_fail:
            user = su_fail.group("user")
            target_user = su_fail.group("target_user")
            tty = su_fail.group("tty")
            details.update({"target_user": target_user, "tty": tty})
            return ParsedLogEntry(
                line_number=line_number,
                raw_text=line,
                timestamp=dt,
                log_type="auth",
                event_type="su_failure",
                user=user,
                message=msg,
                details=details,
            )

        su_succ = SU_SUCCESS_RE.search(msg)
        if su_succ:
            target_user = su_succ.group("target_user") or su_succ.group("target_user2")
            user = su_succ.group("user") or su_succ.group("user2")
            tty = su_succ.group("tty")
            details.update({"target_user": target_user, "tty": tty})
            return ParsedLogEntry(
                line_number=line_number,
                raw_text=line,
                timestamp=dt,
                log_type="auth",
                event_type="su_success",
                user=user,
                message=msg,
                details=details,
            )

        # 8. General auth message
        return ParsedLogEntry(
            line_number=line_number,
            raw_text=line,
            timestamp=dt,
            log_type="auth",
            event_type="auth_generic",
            message=msg,
            details=details,
        )
