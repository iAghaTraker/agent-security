import datetime
import logging
import re
from pathlib import Path

IP = r"[0-9A-Fa-f:.]{3,64}"
FOUND = re.compile(rf"\bFound\s+({IP})\b")
BAN = re.compile(rf"\bBan\s+({IP})\b")
UNBAN = re.compile(rf"\bUnban\s+({IP})\b")


def _message(kind, ip, service="sshd"):
    return (
        f"🚨 Fail2ban Alert\n\nType:\n{kind}\n\nService:\n{service}\n\nIP:\n{ip}\n\n"
        f"Time:\n{datetime.datetime.now().astimezone().isoformat(timespec='seconds')}"
    )


def _clean_ip(value):
    return str(value or "").strip()[:64]


def run(config, telegram, stop):
    log = logging.getLogger(__name__)
    path = Path(getattr(config, "fail2ban_log", "/var/log/fail2ban.log"))
    ban_cooldown = getattr(config, "fail2ban_ban_cooldown_seconds", 0)
    unban_cooldown = getattr(config, "fail2ban_unban_cooldown_seconds", 0)
    found_cooldown = getattr(config, "fail2ban_found_cooldown_seconds", 300)
    stream = None
    inode = None
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
            match = BAN.search(line)
            if match:
                ip = _clean_ip(match.group(1))
                telegram.send(f"fail2ban-ban:{ip}", _message("Ban", ip), ban_cooldown)
                continue
            match = UNBAN.search(line)
            if match:
                ip = _clean_ip(match.group(1))
                telegram.send(f"fail2ban-unban:{ip}", _message("Unban", ip), unban_cooldown)
                continue
            match = FOUND.search(line)
            if match:
                ip = _clean_ip(match.group(1))
                telegram.send(f"fail2ban-found:{ip}", _message("Failed Login Detected", ip), found_cooldown)
        except OSError:
            log.exception("Fail2ban monitor failed")
            if stream is not None:
                stream.close()
                stream = None
            stop.wait(2)
        except Exception:
            log.exception("Fail2ban monitor failed")
            stop.wait(2)
