# ==============================================================================
# Product:       lh-log-sentry (lh-sentry)
# Module:        tests.test_parsers
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for log parsers (Auth, Web, Syslog, Detector)."""

from lh_log_sentry.models import LogType
from lh_log_sentry.parsers.auth import AuthLogParser
from lh_log_sentry.parsers.detector import detect_log_type, get_parser
from lh_log_sentry.parsers.syslog import SyslogParser
from lh_log_sentry.parsers.utils import parse_syslog_timestamp, parse_web_timestamp
from lh_log_sentry.parsers.web import WebLogParser


def test_parse_syslog_timestamp_bsd() -> None:
    dt, remainder = parse_syslog_timestamp("Oct 11 14:32:05 myhost sshd: test", default_year=2026)
    assert dt is not None
    assert dt.month == 10
    assert dt.day == 11
    assert dt.hour == 14
    assert dt.minute == 32
    assert dt.second == 5
    assert remainder == "myhost sshd: test"


def test_parse_syslog_timestamp_iso() -> None:
    dt, remainder = parse_syslog_timestamp("2026-11-03T08:15:22.123456+00:00 myhost sudo: msg")
    assert dt is not None
    assert dt.year == 2026
    assert dt.month == 11
    assert dt.day == 3
    assert dt.hour == 8
    assert dt.minute == 15
    assert dt.second == 22
    assert remainder == "myhost sudo: msg"


def test_parse_web_timestamp() -> None:
    dt = parse_web_timestamp("10/Oct/2026:13:55:36 +0000")
    assert dt is not None
    assert dt.year == 2026
    assert dt.month == 10
    assert dt.day == 10
    assert dt.hour == 13
    assert dt.minute == 55
    assert dt.second == 36


def test_auth_parser_ssh_failed() -> None:
    parser = AuthLogParser()
    line = "Nov  3 10:00:01 srv sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 45123 ssh2"
    entry = parser.parse_line(1, line)
    assert entry is not None
    assert entry.event_type == "ssh_failed_login"
    assert entry.user == "admin"
    assert entry.source_ip == "192.168.1.100"
    assert entry.details["port"] == 45123
    assert entry.details["is_invalid_user"] is True


def test_auth_parser_ssh_accepted() -> None:
    parser = AuthLogParser()
    line = "Nov  3 10:05:00 srv sshd[1245]: Accepted publickey for alice from 10.0.0.50 port 55432 ssh2"
    entry = parser.parse_line(2, line)
    assert entry is not None
    assert entry.event_type == "ssh_accepted_login"
    assert entry.user == "alice"
    assert entry.source_ip == "10.0.0.50"
    assert entry.details["auth_method"] == "publickey"


def test_auth_parser_ssh_disconnect_preauth() -> None:
    parser = AuthLogParser()
    line = "Nov  3 10:06:00 srv sshd[1250]: Connection closed by authenticating user root 192.168.1.200 port 40001 [preauth]"
    entry = parser.parse_line(3, line)
    assert entry is not None
    assert entry.event_type == "ssh_disconnect_preauth"
    assert entry.source_ip == "192.168.1.200"


def test_auth_parser_pam_failure() -> None:
    parser = AuthLogParser()
    line = "Nov  3 10:10:00 srv sudo[500]: pam_unix(sudo:auth): authentication failure; logname=bob uid=1001 euid=0 tty=/dev/pts/1 ruser=bob rhost=  user=bob"
    entry = parser.parse_line(4, line)
    assert entry is not None
    assert entry.event_type == "sudo_auth_failure"
    assert entry.user == "bob"


def test_auth_parser_sudo_execution() -> None:
    parser = AuthLogParser()
    line = "Nov  3 10:12:00 srv sudo[550]:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id"
    entry = parser.parse_line(5, line)
    assert entry is not None
    assert entry.event_type == "sudo_command"
    assert entry.user == "alice"
    assert entry.details["target_user"] == "root"
    assert entry.details["command"] == "/usr/bin/id"


def test_auth_parser_sudo_not_in_sudoers() -> None:
    parser = AuthLogParser()
    line = "Nov  3 10:15:00 srv sudo[600]:    mallory : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"
    entry = parser.parse_line(6, line)
    assert entry is not None
    assert entry.event_type == "sudo_unauthorized"
    assert entry.user == "mallory"


def test_auth_parser_su_failure() -> None:
    parser = AuthLogParser()
    line = "Nov  3 10:20:00 srv su[700]: FAILED SU (to root) eve on pts/2"
    entry = parser.parse_line(7, line)
    assert entry is not None
    assert entry.event_type == "su_failure"
    assert entry.user == "eve"
    assert entry.details["target_user"] == "root"


def test_auth_parser_empty_line() -> None:
    parser = AuthLogParser()
    assert parser.parse_line(1, "   ") is None
    assert parser.parse_line(2, "Invalid line without date") is None


def test_web_parser_combined() -> None:
    parser = WebLogParser()
    line = '192.168.1.10 - admin [10/Oct/2026:13:55:36 +0000] "GET /admin/dashboard HTTP/1.1" 200 4500 "https://example.com" "Mozilla/5.0"'
    entry = parser.parse_line(1, line)
    assert entry is not None
    assert entry.source_ip == "192.168.1.10"
    assert entry.user == "admin"
    assert entry.http_method == "GET"
    assert entry.http_path == "/admin/dashboard"
    assert entry.http_version == "HTTP/1.1"
    assert entry.status_code == 200
    assert entry.referer == "https://example.com"
    assert entry.user_agent == "Mozilla/5.0"


def test_web_parser_common_and_url_decoding() -> None:
    parser = WebLogParser()
    line = '203.0.113.5 - - [10/Oct/2026:14:00:00 +0000] "GET /files?path=%2e%2e%2fetc%2fpasswd HTTP/1.1" 404 150'
    entry = parser.parse_line(1, line)
    assert entry is not None
    assert entry.source_ip == "203.0.113.5"
    assert entry.status_code == 404
    assert "../etc/passwd" in entry.details["decoded_path"]


def test_web_parser_malformed() -> None:
    parser = WebLogParser()
    assert parser.parse_line(1, "") is None
    assert parser.parse_line(2, "This is not a web log line") is None


def test_syslog_parser() -> None:
    parser = SyslogParser()
    line = "Nov  3 12:00:00 webnode crond[999]: (root) CMD (/usr/libexec/atrun)"
    entry = parser.parse_line(1, line)
    assert entry is not None
    assert entry.log_type == "syslog"
    assert entry.details["hostname"] == "webnode"
    assert entry.details["program"] == "crond"


def test_detector_selection() -> None:
    web_sample = [
        '192.168.1.10 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 1204',
        '192.168.1.11 - - [10/Oct/2026:13:55:37 +0000] "GET /about HTTP/1.1" 200 450',
    ]
    assert detect_log_type(web_sample) == LogType.WEB
    p, t = get_parser(LogType.AUTO, web_sample)
    assert isinstance(p, WebLogParser)
    assert t == LogType.WEB

    auth_sample = [
        "Nov  3 10:00:01 srv sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 45123 ssh2",
        "Nov  3 10:00:02 srv sudo[550]:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls",
    ]
    assert detect_log_type(auth_sample) == LogType.AUTH
    p_auth, t_auth = get_parser("auth")
    assert isinstance(p_auth, AuthLogParser)
    assert t_auth == LogType.AUTH
