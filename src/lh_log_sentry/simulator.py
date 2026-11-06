# ==============================================================================
# Product:       lh-log-sentry (lh-sentry)
# Module:        src.lh_log_sentry.simulator
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Synthetic log generator for attack simulations."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta
from pathlib import Path

from lh_log_sentry.models import SimulationScenario


def generate_ssh_bruteforce_logs(
    start_time: datetime | None = None,
    burst_count: int = 10,
    attacker_ip: str = "198.51.100.42",
    target_users: Sequence[str] | None = None,
) -> list[str]:
    """Generate synthetic OpenSSH logs depicting a brute-force velocity attack."""
    base_time = start_time or datetime.now()
    users = list(target_users or ["root", "admin", "test", "deploy", "guest", "ubuntu", "oracle"])
    lines: list[str] = []

    # 1. Baseline legitimate traffic
    t1 = base_time - timedelta(minutes=5)
    lines.append(
        f"{t1.strftime('%b %d %H:%M:%S')} sec-node sshd[10412]: Accepted publickey for devuser from 10.0.0.15 port 52140 ssh2"
    )
    lines.append(
        f"{(t1 + timedelta(seconds=10)).strftime('%b %d %H:%M:%S')} sec-node systemd[1]: Started Session 42 of User devuser."
    )

    # 2. Brute-force burst within a 60-second window
    current_time = base_time
    for i in range(burst_count):
        user = users[i % len(users)]
        port = 40000 + i
        t_str = current_time.strftime("%b %d %H:%M:%S")
        if i % 3 == 0:
            lines.append(
                f"{t_str} sec-node sshd[{20000 + i}]: Invalid user {user} from {attacker_ip} port {port}"
            )
        lines.append(
            f"{t_str} sec-node sshd[{20000 + i}]: Failed password for invalid user {user} from {attacker_ip} port {port} ssh2"
        )
        current_time += timedelta(seconds=2)

    # 3. Post-attack disconnect
    t_post = current_time + timedelta(seconds=5)
    lines.append(
        f"{t_post.strftime('%b %d %H:%M:%S')} sec-node sshd[20099]: Connection closed by authenticating user {attacker_ip} port 40099 [preauth]"
    )
    return lines


def generate_sudo_escalation_logs(
    start_time: datetime | None = None,
) -> list[str]:
    """Generate synthetic auth logs depicting sudo and privilege escalation attempts."""
    base_time = start_time or datetime.now()
    lines: list[str] = []

    # 1. Normal legitimate sudo activity
    t0 = base_time - timedelta(minutes=2)
    lines.append(
        f"{t0.strftime('%b %d %H:%M:%S')} sec-node sudo[15001]:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"
    )

    # 2. Unauthorized user not in sudoers
    t1 = base_time - timedelta(minutes=1)
    lines.append(
        f"{t1.strftime('%b %d %H:%M:%S')} sec-node sudo[15020]:    bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash"
    )

    # 3. Sudo password attempt failures
    t2 = base_time - timedelta(seconds=30)
    lines.append(
        f"{t2.strftime('%b %d %H:%M:%S')} sec-node sudo[15033]: pam_unix(sudo:auth): authentication failure; logname=mallory uid=1002 euid=0 tty=/dev/pts/2 ruser=mallory rhost=  user=mallory"
    )
    lines.append(
        f"{(t2 + timedelta(seconds=2)).strftime('%b %d %H:%M:%S')} sec-node sudo[15033]:    mallory : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/mallory ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    )

    # 4. Failed su attempt to root
    t3 = base_time - timedelta(seconds=15)
    lines.append(
        f"{t3.strftime('%b %d %H:%M:%S')} sec-node su[15045]: FAILED SU (to root) eve on pts/3"
    )

    # 5. Suspicious root shell spawn
    t4 = base_time
    lines.append(
        f"{t4.strftime('%b %d %H:%M:%S')} sec-node sudo[15050]:    charlie : TTY=pts/4 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"
    )

    return lines


def generate_web_attack_logs(
    start_time: datetime | None = None,
    burst_count: int = 8,
    attacker_ip: str = "203.0.113.88",
) -> list[str]:
    """Generate synthetic Nginx/Apache Combined logs depicting path traversal, SQLi, XSS, and stuffing."""
    base_time = start_time or datetime.now()
    lines: list[str] = []

    # 1. Normal traffic
    t0 = base_time - timedelta(minutes=3)
    lines.append(
        f'192.168.1.100 - - [{t0.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET / HTTP/1.1" 200 4523 "https://example.com" "Mozilla/5.0 (X11; Linux x86_64)"'
    )
    lines.append(
        f'192.168.1.100 - - [{(t0 + timedelta(seconds=1)).strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET /static/css/main.css HTTP/1.1" 200 1204 "https://example.com/" "Mozilla/5.0"'
    )

    # 2. Path traversal attack
    t1 = base_time - timedelta(minutes=2)
    lines.append(
        f'{attacker_ip} - - [{t1.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET /../../etc/passwd HTTP/1.1" 404 162 "-" "curl/8.5.0"'
    )
    lines.append(
        f'{attacker_ip} - - [{(t1 + timedelta(seconds=2)).strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET /files?name=%2e%2e%2f%2e%2e%2fetc%2fshadow HTTP/1.1" 403 162 "-" "curl/8.5.0"'
    )
    lines.append(
        f'{attacker_ip} - - [{(t1 + timedelta(seconds=4)).strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET /.env HTTP/1.1" 404 162 "-" "curl/8.5.0"'
    )

    # 3. SQL Injection probes
    t2 = base_time - timedelta(minutes=1)
    lines.append(
        f'{attacker_ip} - - [{t2.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET /products?id=1%20UNION%20SELECT%20username,%20password%20FROM%20users-- HTTP/1.1" 500 523 "-" "sqlmap/1.7"'
    )
    lines.append(
        f'{attacker_ip} - - [{(t2 + timedelta(seconds=5)).strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET /search?query=\' OR 1=1;-- HTTP/1.1" 200 3410 "-" "Mozilla/5.0"'
    )

    # 4. XSS attack
    t3 = base_time - timedelta(seconds=40)
    lines.append(
        f'{attacker_ip} - - [{t3.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "POST /comments?msg=<script>alert(document.cookie)</script> HTTP/1.1" 200 420 "-" "Mozilla/5.0"'
    )

    # 5. Credential stuffing burst (401/403 responses)
    current_time = base_time - timedelta(seconds=20)
    for i in range(burst_count):
        t_str = current_time.strftime("%d/%b/%Y:%H:%M:%S")
        status = 401 if i % 2 == 0 else 403
        lines.append(
            f'{attacker_ip} - - [{t_str} +0000] "POST /api/v1/auth/login HTTP/1.1" {status} 89 "-" "Go-http-client/1.1"'
        )
        current_time += timedelta(seconds=1)

    return lines


def generate_scenario(
    scenario: SimulationScenario | str,
    output_path: Path | str | None = None,
    count: int = 10,
) -> list[str]:
    """Generate synthetic scenario logs and optionally write to file.

    Args:
        scenario: The attack scenario to simulate.
        output_path: Optional destination file path.
        count: Number of attack iterations or burst entries.

    Returns:
        List of generated log lines.
    """
    resolved = SimulationScenario(scenario) if isinstance(scenario, str) else scenario
    lines: list[str]

    if resolved == SimulationScenario.SSH_BRUTEFORCE:
        lines = generate_ssh_bruteforce_logs(burst_count=count)
    elif resolved == SimulationScenario.SUDO_ESCALATION:
        lines = generate_sudo_escalation_logs()
    elif resolved == SimulationScenario.WEB_ATTACK:
        lines = generate_web_attack_logs(burst_count=count)
    else:
        raise ValueError(f"Unknown scenario: {scenario}")

    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return lines
