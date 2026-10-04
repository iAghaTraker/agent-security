import logging
import re
from collections import deque
from pathlib import Path

from ..approval.service import command_hash, redact_command

DEFAULT_DANGEROUS_BINARIES = (
    "apt",
    "apt-get",
    "chmod",
    "chown",
    "crontab",
    "curl",
    "dd",
    "dpkg",
    "fdisk",
    "iptables",
    "mkfs",
    "mv",
    "nft",
    "partprobe",
    "poweroff",
    "reboot",
    "rm",
    "rmdir",
    "scp",
    "shutdown",
    "shred",
    "ssh",
    "systemctl",
    "truncate",
    "visudo",
    "wget",
)

DEFAULT_AUDIT_KEY = "agent-danger"


def _build_syscall_re(audit_key: str):
    key = re.escape(audit_key)
    return re.compile(
        r"type=SYSCALL\b.*?audit\((?P<serial>[\d.]+):(?P<event>\d+)\)"
        r".*?\buid=(\d+).*?key=[\"']" + key + r"[\"']"
    )


def _unescape(value):
    return value.replace('\\"', '"').replace("\\\\", "\\")


def _is_dangerous(executable, dangerous):
    return Path(executable).name.lower() in dangerous


def _alert(executable, args, uid):
    command = " ".join([executable, *args])
    return (
        f"🚨 Dangerous Command Detected\n\nUser UID:\n{uid}\n\nExecutable:\n{executable}\n\n"
        f"Command:\n{redact_command(command, 700)}\n\n"
        "Execution was not blocked; use the approval gate for pre-approval."
    )


def run(config, telegram, stop):
    log = logging.getLogger(__name__)
    path = Path(getattr(config, "audit_log", "/var/log/audit/audit.log"))
    audit_key = getattr(config, "audit_key", DEFAULT_AUDIT_KEY)
    dangerous = frozenset(getattr(config, "dangerous_binaries", None) or DEFAULT_DANGEROUS_BINARIES)
    cooldown = getattr(config, "command_cooldown_seconds", 10)
    window = getattr(config, "approval_match_window_seconds", 120)
    history_size = max(1, getattr(config, "command_history_size", 1000))

    syscall_re = _build_syscall_re(audit_key)
    execve_re = re.compile(r"type=EXECVE\b.*?audit\((?P<serial>[\d.]+):(?P<event>\d+)\)")
    argument_re = re.compile(r"\ba(\d+)=\"((?:\\.|[^\"])*)\"")

    stream = None
    inode = None
    seen: deque[str] = deque()
    seen_values: set[str] = set()
    pending_syscalls: dict[str, int] = {}

    from ..approval.service import RequestStore

    store = RequestStore()

    while not stop.is_set():
        try:
            if stream is None:
                if not path.is_file():
                    stop.wait(2)
                    continue
                stream = path.open("r", encoding="utf-8", errors="replace")
                stream.seek(0, 2)
                inode = path.stat().st_ino
            line = stream.readline()
            if not line:
                try:
                    current_inode = path.stat().st_ino
                except OSError:
                    current_inode = None
                if current_inode != inode:
                    stream.close()
                    stream = None
                    inode = None
                    continue
                stop.wait(1)
                continue

            syscall_match = syscall_re.search(line)
            if syscall_match is not None:
                if syscall_match.group(3) != "0":
                    pending_syscalls[f"{syscall_match.group(1)}:{syscall_match.group(2)}"] = int(
                        syscall_match.group(3)
                    )
                continue

            execute_match = execve_re.search(line)
            if execute_match is None:
                continue
            event_id = f"{execute_match.group(1)}:{execute_match.group(2)}"
            uid = pending_syscalls.pop(event_id, 0)
            if uid == 0:
                continue

            arguments = sorted(
                (int(index), _unescape(value)) for index, value in argument_re.findall(line)
            )
            if not arguments:
                continue
            executable = arguments[0][1]
            if not _is_dangerous(executable, dangerous):
                continue
            args = [value for _, value in arguments[1:]]
            digest = command_hash("\0".join([executable, *args]))
            event_key = f"{event_id}:{uid}:{digest}"
            if event_key in seen_values:
                continue
            seen_values.add(event_key)
            seen.append(event_key)
            while len(seen) > history_size:
                seen_values.discard(seen.popleft())
            if store.recent_match("exec", uid, digest, window):
                continue
            telegram.send(
                f"audit-danger:{uid}:{Path(executable).name}",
                _alert(executable, args, uid),
                cooldown,
            )
        except OSError:
            log.exception("Audit command monitor failed")
            if stream is not None:
                stream.close()
                stream = None
            stop.wait(2)
        except Exception:
            log.exception("Audit command monitor failed")
            stop.wait(2)
