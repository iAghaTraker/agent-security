#!/usr/bin/env python3
from __future__ import annotations

import os
import shlex
import sys
import time
from pathlib import Path
from typing import Any

from .service import (
    BanStore,
    DEFAULT_BAN_SECONDS,
    DEFAULT_TIMEOUT,
    RequestStore,
    audit,
    bypass_active,
    clean_text,
    clear_bypass,
    command_hash,
    normalize_identity,
    redact_command,
    set_bypass,
    setting,
    setting_bool,
    setting_int,
    status,
)


def _root_only() -> bool:
    return os.geteuid() == 0


def _exempt_user(user: str) -> bool:
    values = {normalize_identity(value) for value in setting("APPROVAL_EXEMPT_USERS", "").split(",")}
    return normalize_identity(user) in values


def _exempt_tty(tty: str) -> bool:
    values = {clean_text(value, 160) for value in setting("APPROVAL_EXEMPT_TTYS", "/dev/console").split(",") if clean_text(value, 160)}
    return clean_text(tty, 160) in values


def _fail_mode_closed() -> bool:
    return setting("APPROVAL_FAIL_MODE", "closed").strip().lower() not in {"open", "fail-open"}


def _caller_uid() -> int:
    try:
        return os.stat(f"/proc/{os.getppid()}").st_uid
    except OSError:
        try:
            return os.getuid()
        except Exception:
            return -1


def _sudo_command_from_pid(pid: int) -> str:
    try:
        executable = os.path.basename(os.readlink(f"/proc/{pid}/exe"))
        if executable not in {"sudo", "sudo.real"}:
            return ""
        environment = Path(f"/proc/{pid}/environ").read_bytes()[:65536]
        for item in environment.split(b"\0"):
            if item.startswith(b"SUDO_COMMAND="):
                command = item.split(b"=", 1)[1].decode("utf-8", "replace").strip()
                if command:
                    return command[:4096]
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()[:16384]
        arguments = [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]
        if not arguments:
            return ""
        options_with_values = {"-C", "-D", "-g", "-h", "-p", "-R", "-T", "-U", "-u"}
        index = 1
        while index < len(arguments):
            argument = arguments[index]
            if argument == "--":
                index += 1
                break
            if argument in options_with_values:
                index += 2
                continue
            if argument.startswith("-"):
                index += 1
                continue
            break
        command = arguments[index:]
        return shlex.join(command)[:4096] if command else ""
    except (OSError, ValueError):
        return ""


def _parent_sudo_command() -> str:
    pid = os.getppid()
    for _ in range(5):
        if pid <= 1:
            break
        command = _sudo_command_from_pid(pid)
        if command:
            return command
        try:
            status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
            parent_line = next(line for line in status.splitlines() if line.startswith("PPid:"))
            pid = int(parent_line.split()[1])
        except (OSError, StopIteration, ValueError):
            break
    return ""


def _wait_for_decision(service: str, user: str, ip: str, command: str, store: RequestStore, bans: BanStore) -> int:
    timeout = setting_int("APPROVAL_REQUEST_TIMEOUT", DEFAULT_TIMEOUT, 30, 900)
    ban_seconds = setting_int("APPROVAL_BAN_SECONDS", DEFAULT_BAN_SECONDS, 60, 604800)
    safe_user = clean_text(user, 128)
    safe_ip = clean_text(ip, 128)
    safe_command = redact_command(command, setting_int("APPROVAL_MAX_COMMAND", 700, 100, 2000)) if service == "sudo" else ""
    request = store.create({
        "service": service,
        "user": safe_user,
        "ip": safe_ip,
        "command": safe_command,
        "command_hash": command_hash(command) if service == "sudo" and command else "",
        "uid": _caller_uid(),
        "pid": os.getpid(),
        "tty": clean_text(os.environ.get("PAM_TTY", ""), 160),
    })
    value = str(request["id"])
    audit("request_created", request_id=value, service=service, user=safe_user, ip=safe_ip, command_hash=request.get("command_hash", ""))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = store.read(value)
        if current is None:
            audit("request_state_missing", request_id=value, service=service, user=safe_user, ip=safe_ip)
            return 1
        status_value = current.get("status")
        if status_value == "approved":
            consumed = store.consume(value, {"approved"})
            if consumed is None:
                return 1
            audit("request_approved", request_id=value, service=service, user=safe_user, ip=safe_ip)
            return 0
        if status_value == "rejected":
            # Claim the single-use decision first; only a request we actually
            # consumed may trigger a ban.
            consumed = store.consume(value, {"rejected"})
            if consumed is None:
                return 1
            if service == "sshd":
                try:
                    bans.add(safe_user, safe_ip, "Telegram reject", ban_seconds)
                except Exception as exc:
                    audit("ban_write_failed", request_id=value, service=service, user=safe_user, ip=safe_ip, error=type(exc).__name__)
            audit("request_rejected", request_id=value, service=service, user=safe_user, ip=safe_ip)
            return 1
        if status_value == "expired":
            return 1
        time.sleep(0.5)
    store.expire(value)
    audit("request_timeout", request_id=value, service=service, user=safe_user, ip=safe_ip)
    return 1


def gate(service: str) -> int:
    if not setting_bool("APPROVAL_ENABLED", False):
        return 0
    user = os.environ.get("PAM_USER", "").strip()
    ip = os.environ.get("PAM_RHOST", "").strip()
    tty = os.environ.get("PAM_TTY", "").strip()
    if not user or not service or (service not in {"sshd", "sudo"}):
        audit("invalid_pam_environment", service=service, user=clean_text(user, 128), ip=clean_text(ip, 128))
        return 1
    if _exempt_user(user) or _exempt_tty(tty) or bypass_active():
        return 0
    if service == "sshd" and not ip:
        # Without a remote host we cannot attribute or ban the attempt, so the
        # request can never be safely approved.
        audit("ssh_missing_remote_host", user=clean_text(user, 128))
        return 1
    store = RequestStore()
    bans = BanStore()
    if service == "sshd":
        active = bans.active(user, ip)
        if active is not None:
            audit("ssh_banned", user=clean_text(user, 128), ip=clean_text(ip, 128), expires_at=active.get("expires_at"))
            return 1
    command = ""
    if service == "sudo":
        command = os.environ.get("SUDO_COMMAND", "").strip() or _parent_sudo_command()
    return _wait_for_decision(service, user, ip, command, store, bans)


def admin_command(arguments: list[str]) -> int:
    if not _root_only():
        return 1
    if not arguments:
        return 2
    command = arguments[0]
    if command == "status":
        print(status())
        return 0
    if command == "unban":
        if len(arguments) < 2 or len(arguments) > 3:
            return 2
        removed = BanStore().remove(arguments[1], arguments[2] if len(arguments) == 3 else None)
        print(f"removed={removed}")
        return 0
    if command == "bypass":
        if len(arguments) < 2 or arguments[1] not in {"on", "off"}:
            return 2
        if arguments[1] == "off":
            clear_bypass()
            print("bypass=off")
            return 0
        if len(arguments) > 3:
            return 2
        try:
            minutes = int(arguments[2]) if len(arguments) == 3 else 30
        except ValueError:
            return 2
        expires = set_bypass(minutes)
        print(f"bypass=on expires={expires}")
        return 0
    return 2


def main() -> int:
    if len(sys.argv) < 2:
        return 2
    try:
        if sys.argv[1] in {"status", "unban", "bypass"}:
            return admin_command(sys.argv[1:])
        return gate(sys.argv[1])
    except Exception as exc:
        audit("helper_error", service=sys.argv[1] if len(sys.argv) > 1 else "", error=type(exc).__name__)
        if _fail_mode_closed():
            return 1
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
