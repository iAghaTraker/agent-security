import os
from dataclasses import dataclass, field

DEFAULT_SERVICES = ("nginx.service", "redis-server.service")
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

ALL_MONITORS = ("ssh", "journal", "filesystem", "crowdsec", "fail2ban", "commands")


def _int_env(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


def _list_env(name: str) -> tuple[str, ...] | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    items = tuple(item.strip() for item in raw.split(",") if item.strip())
    return items or None


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on", "enabled"}


def _disabled_env() -> frozenset[str]:
    items = _list_env("AGENT_DISABLE_MONITORS") or ()
    return frozenset(item.strip().lower() for item in items if item.strip())


def _path_env(name: str, default: str) -> str:
    return os.environ.get(name, "").strip() or default


@dataclass(frozen=True)
class Config:
    token: str
    chat_id: str

    # Alerting behaviour
    cooldown_seconds: int = 300
    log_path: str = "/var/log/agent-security.log"

    # Telegram identity allowed to act on approval requests.
    owner_id: str = ""
    admin_ids: frozenset[str] = field(default_factory=frozenset)

    # Monitor toggles
    disabled_monitors: frozenset[str] = field(default_factory=frozenset)

    # Journal monitor
    services: tuple[str, ...] = field(default=DEFAULT_SERVICES)
    journal_keywords: tuple[str, ...] = (
        "failed",
        "crash",
        "stopped",
        "restart",
        "watchdog",
    )
    journal_cooldown_seconds: int = 300

    # Filesystem monitor
    watch_roots: tuple[str, ...] = ("/etc/nginx", "/etc/ssh", "/etc", "/opt")
    skip_names: tuple[str, ...] = (
        "node_modules",
        ".next",
        "venv",
        "__pycache__",
        ".git",
        "backups",
    )
    file_scan_seconds: int = 3
    file_max_bytes: int = 10_000_000
    file_max_events_per_scan: int = 30
    file_confirm_scans: int = 2
    sudo_audit_log: str = "/var/log/agent-security.log"

    # CrowdSec monitor
    crowdsec_scan_seconds: int = 5
    crowdsec_cooldown_seconds: int = 60

    # Fail2ban monitor
    fail2ban_log: str = "/var/log/fail2ban.log"
    fail2ban_ban_cooldown_seconds: int = 0
    fail2ban_unban_cooldown_seconds: int = 0
    fail2ban_found_cooldown_seconds: int = 300

    # Dangerous-command monitor
    audit_log: str = "/var/log/audit/audit.log"
    audit_key: str = "agent-danger"
    dangerous_binaries: tuple[str, ...] = field(default=DEFAULT_DANGEROUS_BINARIES)
    command_cooldown_seconds: int = 10
    approval_match_window_seconds: int = 120
    command_history_size: int = 1000

    def monitor_enabled(self, name: str) -> bool:
        return name.strip().lower() not in self.disabled_monitors

    def is_admin(self, telegram_id: str) -> bool:
        sender = str(telegram_id or "").strip()
        if self.owner_id:
            return sender == self.owner_id
        return sender in self.admin_ids

    @property
    def enabled_monitors(self) -> tuple[str, ...]:
        return tuple(name for name in ALL_MONITORS if self.monitor_enabled(name))

    @classmethod
    def from_env(cls):
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
        if not token or not chat_id:
            raise RuntimeError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required")

        keywords = _list_env("AGENT_JOURNAL_KEYWORDS")
        dangerous = _list_env("AGENT_DANGEROUS_BINARIES")
        skip_names = _list_env("AGENT_SKIP_NAMES")
        owner_id = _path_env("AGENT_OWNER_ID", "")
        admins = _list_env("AGENT_ADMIN_IDS") or ()

        return cls(
            token=token,
            chat_id=chat_id,
            cooldown_seconds=_int_env("AGENT_COOLDOWN_SECONDS", 300, 0),
            log_path=_path_env("AGENT_LOG_PATH", "/var/log/agent-security.log"),
            owner_id=owner_id,
            admin_ids=frozenset(admins),
            disabled_monitors=_disabled_env(),
            services=_list_env("AGENT_SERVICES") or DEFAULT_SERVICES,
            journal_keywords=keywords
            or ("failed", "crash", "stopped", "restart", "watchdog"),
            journal_cooldown_seconds=_int_env("AGENT_JOURNAL_COOLDOWN_SECONDS", 300, 0),
            watch_roots=_list_env("AGENT_WATCH_ROOTS") or ("/etc/nginx", "/etc/ssh", "/etc", "/opt"),
            skip_names=skip_names or ("node_modules", ".next", "venv", "__pycache__", ".git", "backups"),
            file_scan_seconds=_int_env("AGENT_FILE_SCAN_SECONDS", 3, 1),
            file_max_bytes=_int_env("AGENT_FILE_MAX_BYTES", 10_000_000, 1),
            file_max_events_per_scan=_int_env("AGENT_FILE_MAX_EVENTS", 30, 1),
            file_confirm_scans=_int_env("AGENT_FILE_CONFIRM_SCANS", 2, 1),
            sudo_audit_log=_path_env("AGENT_SUDO_AUDIT_LOG", "/var/log/agent-security.log"),
            crowdsec_scan_seconds=_int_env("AGENT_CROWDSEC_SCAN_SECONDS", 5, 1),
            crowdsec_cooldown_seconds=_int_env("AGENT_CROWDSEC_COOLDOWN_SECONDS", 60, 0),
            fail2ban_log=_path_env("AGENT_FAIL2BAN_LOG", "/var/log/fail2ban.log"),
            fail2ban_ban_cooldown_seconds=_int_env("AGENT_FAIL2BAN_BAN_COOLDOWN", 0, 0),
            fail2ban_unban_cooldown_seconds=_int_env("AGENT_FAIL2BAN_UNBAN_COOLDOWN", 0, 0),
            fail2ban_found_cooldown_seconds=_int_env("AGENT_FAIL2BAN_FOUND_COOLDOWN", 300, 0),
            audit_log=_path_env("AGENT_AUDIT_LOG", "/var/log/audit/audit.log"),
            audit_key=_path_env("AGENT_AUDIT_KEY", "agent-danger"),
            dangerous_binaries=tuple(item.lower() for item in dangerous)
            if dangerous
            else DEFAULT_DANGEROUS_BINARIES,
            command_cooldown_seconds=_int_env("AGENT_COMMAND_COOLDOWN_SECONDS", 10, 0),
            approval_match_window_seconds=_int_env("AGENT_APPROVAL_MATCH_WINDOW", 120, 0),
            command_history_size=_int_env("AGENT_COMMAND_HISTORY_SIZE", 1000, 1),
        )
