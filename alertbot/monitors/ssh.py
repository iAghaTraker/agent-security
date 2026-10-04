import logging
import re
import subprocess
import time
from collections import defaultdict, deque
from pathlib import Path

LOGIN = re.compile(r"sshd(?:\[\d+\])?:\s+Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)")
FAIL = re.compile(r"sshd(?:\[\d+\])?:\s+Failed\s+\S+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)")
INVALID = re.compile(r"sshd(?:\[\d+\])?:\s+Invalid user\s+(\S+)\s+from\s+(\S+)")
CLOSED = re.compile(r"sshd(?:\[\d+\])?:\s+Connection closed by (?:authenticating user\s+)?(\S+)\s+(\S+)(?:\s+port|\s+\[preauth\])")
CLOSED_IP = re.compile(r"sshd(?:\[\d+\])?:\s+Connection closed by (\S+)(?:\s+port|\s+\[preauth\])")
SUDO = re.compile(r"sudo(?:\[\d+\])?:\s+(\S+)\s+:.*COMMAND=(.+)")

FAIL_WINDOW_SECONDS = 300
FAIL_THRESHOLD = 5


def _safe(value, limit=160):
    return " ".join(str(value or "").split())[:limit]


def _alert(kind, user, ip, detail=""):
    text = f"🚨 Security Alert\n\nType:\n{kind}\n\nUser:\n{_safe(user)}\n\nIP:\n{_safe(ip)}"
    if detail:
        text += f"\n\nDetail:\n{_safe(detail, 700)}"
    text += f"\n\nTime:\n{time.strftime('%Y-%m-%dT%H:%M:%S%z')}"
    return text


def run(config, telegram, stop):
    log = logging.getLogger(__name__)
    audit_path = Path(getattr(config, "sudo_audit_log", "/var/log/agent-security.log"))
    process = None
    failures = defaultdict(deque)
    while not stop.is_set():
        try:
            if process is None or process.poll() is not None:
                process = subprocess.Popen(
                    ["journalctl", "-f", "-n", "0", "-o", "short-iso", "_COMM=sshd", "+", "_COMM=sudo"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    bufsize=1,
                )
            line = process.stdout.readline()
            if not line:
                stop.wait(1)
                continue
            match = LOGIN.search(line)
            if match:
                method, user, ip = match.groups()
                telegram.send(f"ssh-login:{ip}", _alert("SSH Login Success", user, ip, f"Method: {method}"), 0)
                continue
            match = FAIL.search(line)
            if match:
                user, ip = match.groups()
                now = time.monotonic()
                values = failures[ip]
                values.append(now)
                while values and now - values[0] > FAIL_WINDOW_SECONDS:
                    values.popleft()
                telegram.send(f"ssh-failed:{ip}", _alert("SSH Login Failed", user, ip), 10)
                if len(values) >= FAIL_THRESHOLD:
                    telegram.send(
                        f"ssh-fail-repeat:{ip}",
                        _alert(
                            "Repeated SSH Login Failures",
                            user,
                            ip,
                            f"Attempts in {FAIL_WINDOW_SECONDS // 60} minutes: {len(values)}",
                        ),
                        300,
                    )
                continue
            match = INVALID.search(line)
            if match:
                user, ip = match.groups()
                telegram.send(f"ssh-failed:{ip}", _alert("SSH Login Failed", user, ip, "Invalid user"), 10)
                continue
            match = CLOSED.search(line)
            if match:
                user, ip = match.groups()
                telegram.send(f"ssh-failed:{ip}", _alert("SSH Login Failed", user, ip, "Connection closed before authentication"), 10)
                continue
            match = CLOSED_IP.search(line)
            if match:
                ip = match.group(1)
                telegram.send(f"ssh-failed:{ip}", _alert("SSH Login Failed", "unknown", ip, "Connection closed before authentication"), 10)
                continue
            match = SUDO.search(line)
            if match:
                try:
                    audit_path.parent.mkdir(parents=True, exist_ok=True)
                    with audit_path.open("a", encoding="utf-8") as stream:
                        stream.write(line.rstrip("\n") + "\n")
                except OSError:
                    log.exception("Could not write sudo audit log")
                user, command = match.groups()
                safe_command = redact_command(command.strip(), 700)
                telegram.send(f"sudo:{hash(line)}", _alert("Sudo Command", user, "local", safe_command), 0)
        except FileNotFoundError:
            log.warning("journalctl is not present")
        except Exception:
            log.exception("SSH monitor failed")
        stop.wait(1)
