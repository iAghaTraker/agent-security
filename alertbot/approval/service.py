from __future__ import annotations

import contextlib
import fcntl
import hashlib
import html
import json
import logging
import grp
import os
import pwd
import re
import secrets
import shlex
import socket
import stat
import struct
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlencode
from urllib.request import Request, urlopen

DEFAULT_CONFIG_PATH = "/etc/agent/approval.conf"
DEFAULT_STATE_DIR = "/run/agent-security-alert"
DEFAULT_DATA_DIR = "/var/lib/agent-security-alert"
DEFAULT_LOG_PATH = "/var/log/agent-security-approval.log"
DEFAULT_SOCKET_PATH = "/run/agent-security-approval.sock"
DEFAULT_TIMEOUT = 180
DEFAULT_BAN_SECONDS = 86400
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,80}$")
CONTROL_PATTERN = re.compile(r"[\x00-\x1f\x7f]")


def _read_kv(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as stream:
            for raw in stream:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip("\"'")
    except OSError:
        pass
    return values


def setting(name: str, default: str = "") -> str:
    trusted = os.environ.get("APPROVAL_TRUST_ENV") == "1"
    if trusted and name in os.environ:
        return os.environ[name]
    config_path = os.environ.get("APPROVAL_CONFIG", DEFAULT_CONFIG_PATH) if trusted else DEFAULT_CONFIG_PATH
    return _read_kv(config_path).get(name, default)


def setting_bool(name: str, default: bool = False) -> bool:
    value = setting(name, "1" if default else "0").strip().lower()
    return value in {"1", "true", "yes", "on"}


def setting_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(setting(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


def state_dir() -> Path:
    return Path(setting("APPROVAL_STATE_DIR", DEFAULT_STATE_DIR))


def data_dir() -> Path:
    return Path(setting("APPROVAL_DATA_DIR", DEFAULT_DATA_DIR))


def socket_path() -> Path:
    return Path(setting("APPROVAL_SOCKET", DEFAULT_SOCKET_PATH))


def ensure_dir(path: Path, mode: int = 0o700) -> None:
    existed = path.exists()
    try:
        path.mkdir(parents=True, exist_ok=True, mode=mode)
    except FileExistsError:
        return
    if not existed:
        try:
            os.chmod(path, mode)
        except OSError:
            pass


def _atomic_write(path: Path, payload: dict[str, Any], mode: int = 0o600) -> None:
    ensure_dir(path.parent)
    fd, temporary = tempfile.mkstemp(prefix=".approval-", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        target = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        try:
            os.close(target)
        except OSError:
            pass
        os.replace(temporary, path)
        os.chmod(path, mode)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _read_json(path: Path) -> dict[str, Any]:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 131072:
            raise ValueError("invalid approval state file")
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            value = json.load(stream)
        if not isinstance(value, dict):
            raise ValueError("invalid approval state")
        return value
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


@contextlib.contextmanager
def _locked(path: Path) -> Iterator[None]:
    ensure_dir(path.parent)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def audit(event: str, **fields: Any) -> None:
    record: dict[str, Any] = {"ts": int(time.time()), "event": event}
    for key, value in fields.items():
        if value is None or value == "":
            continue
        if isinstance(value, (str, int, float, bool)):
            record[key] = value
    path = Path(setting("APPROVAL_LOG_FILE", DEFAULT_LOG_PATH))
    encoded = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        ensure_dir(path.parent, 0o750)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, encoded)
        finally:
            os.close(fd)
    except OSError:
        logging.getLogger("agent.approval").warning("approval audit write failed")


def clean_text(value: str, limit: int = 700) -> str:
    value = CONTROL_PATTERN.sub(" ", value or "")
    value = " ".join(value.split())
    return value[:limit]


def normalize_identity(value: str) -> str:
    return clean_text(value, 160).lower()


def redact_command(value: str, limit: int = 700) -> str:
    text = clean_text(value, limit * 2)
    patterns = [
        (re.compile(r"(?i)(--(?:password|passwd|token|secret|api[-_]?key|authorization|cookie)(?:=|\s+))([^\s]+)"), r"\1<redacted>"),
        (re.compile(r"(?i)((?:password|passwd|token|secret|api[_-]?key|authorization|cookie)\s*=\s*)([^\s]+)"), r"\1<redacted>"),
        (re.compile(r"(?i)(https?://[^\s/:@]+:)[^\s/@]+@"), r"\1<redacted>@"),
        (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s]+"), r"\1<redacted>"),
    ]
    for pattern, replacement in patterns:
        text = pattern.sub(replacement, text)
    return text[:limit]


def command_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:24]


def _expiry(record: Any) -> float:
    try:
        return float(record.get("expires_at", 0))
    except (AttributeError, TypeError, ValueError):
        return 0.0


def request_id(value: str) -> str:
    if not REQUEST_ID_PATTERN.fullmatch(value or ""):
        raise ValueError("invalid request id")
    return value


class RequestStore:
    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or (state_dir() / "requests"))
        ensure_dir(self.root)

    def path(self, value: str) -> Path:
        return self.root / f"{request_id(value)}.json"

    def lock_path(self, value: str) -> Path:
        return self.root / f"{request_id(value)}.lock"

    def create(self, payload: dict[str, Any]) -> dict[str, Any]:
        value = secrets.token_urlsafe(24)
        record = dict(payload)
        record.update({"id": value, "status": "pending", "created_at": time.time(), "notified": False})
        with _locked(self.lock_path(value)):
            _atomic_write(self.path(value), record)
        return record

    def read(self, value: str) -> dict[str, Any] | None:
        try:
            return _read_json(self.path(value))
        except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
            return None

    def _update(self, value: str, updater) -> dict[str, Any] | None:
        with _locked(self.lock_path(value)):
            current = self.read(value)
            if current is None:
                return None
            updated = updater(dict(current))
            if updated is None:
                return None
            _atomic_write(self.path(value), updated)
            return updated

    def claim_notification(self, value: str, lease_seconds: int = 30) -> dict[str, Any] | None:
        now = time.time()
        with _locked(self.lock_path(value)):
            current = self.read(value)
            if current is None or current.get("status") != "pending" or current.get("notified"):
                return None
            try:
                notify_after = float(current.get("notify_after", 0))
            except (TypeError, ValueError):
                notify_after = 0
            try:
                notify_until = float(current.get("notify_until", 0))
            except (TypeError, ValueError):
                notify_until = 0
            if notify_after > now or notify_until > now:
                return None
            try:
                attempts = int(current.get("notify_attempts", 0))
            except (TypeError, ValueError):
                attempts = 0
            current["notifying"] = True
            current["notify_until"] = now + max(5, lease_seconds)
            current["notify_attempts"] = attempts + 1
            _atomic_write(self.path(value), current)
            return current

    def mark_notified(self, value: str) -> bool:
        with _locked(self.lock_path(value)):
            current = self.read(value)
            if current is None or current.get("status") != "pending" or current.get("notified"):
                return False
            current["notified"] = True
            current["notifying"] = False
            current["notify_until"] = 0
            _atomic_write(self.path(value), current)
            return True

    def release_notification(self, value: str, retry_after: int = 5) -> bool:
        with _locked(self.lock_path(value)):
            current = self.read(value)
            if current is None or current.get("status") != "pending" or current.get("notified"):
                return False
            current["notifying"] = False
            current["notify_until"] = 0
            current["notify_after"] = time.time() + max(1, retry_after)
            _atomic_write(self.path(value), current)
            return True

    def decide(self, value: str, action: str, actor: str) -> dict[str, Any] | None:
        if action not in {"approve", "reject"}:
            raise ValueError("invalid decision")
        target = "approved" if action == "approve" else "rejected"

        def update(current: dict[str, Any]) -> dict[str, Any] | None:
            if current.get("status") != "pending":
                return None
            current["status"] = target
            current["decision"] = action
            current["actor"] = clean_text(actor, 64)
            current["decided_at"] = time.time()
            return current

        return self._update(value, update)

    def consume(self, value: str, expected: set[str]) -> dict[str, Any] | None:
        def update(current: dict[str, Any]) -> dict[str, Any] | None:
            if current.get("status") not in expected or current.get("consumed_at"):
                return None
            current["consumed_at"] = time.time()
            return current

        return self._update(value, update)

    def expire(self, value: str) -> bool:
        with _locked(self.lock_path(value)):
            current = self.read(value)
            if current is None or current.get("status") != "pending":
                return False
            current["status"] = "expired"
            current["expired_at"] = time.time()
            _atomic_write(self.path(value), current)
            return True

    def pending(self, limit: int = 100) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        try:
            paths = sorted(self.root.glob("*.json"))
        except OSError:
            return result
        for path in paths:
            try:
                value = _read_json(path)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if value.get("status") == "pending":
                try:
                    created = float(value.get("created_at", 0))
                except (TypeError, ValueError):
                    created = 0
                if created and time.time() - created > setting_int("APPROVAL_REQUEST_TIMEOUT", DEFAULT_TIMEOUT, 30, 900) + 30:
                    self.expire(str(value.get("id", "")))
                    self._purge(str(value.get("id", "")))
                    continue
                result.append(value)
            elif value.get("consumed_at") or value.get("status") in {"expired", "rejected"}:
                # Decided requests are kept briefly so the command monitor can
                # match a recent approval, then removed.
                self._maybe_purge(path, value)
            if len(result) >= limit:
                break
        return result

    def _maybe_purge(self, path: Path, value: dict[str, Any]) -> None:
        keep = setting_int("APPROVAL_AUDIT_RETENTION", 3600, 0, 604800)
        stamp = value.get("consumed_at") or value.get("decided_at") or value.get("expired_at") or 0
        try:
            age = time.time() - float(stamp)
        except (TypeError, ValueError):
            return
        if age <= keep:
            return
        try:
            path.unlink()
        except OSError:
            pass

    def _purge(self, value: str) -> None:
        for path in (self.path(value), self.lock_path(value)):
            try:
                path.unlink()
            except OSError:
                pass

    def recent_match(self, service: str, uid: int, digest: str, window_seconds: int) -> bool:
        now = time.time()
        try:
            paths = self.root.glob("*.json")
        except OSError:
            return False
        for path in paths:
            try:
                value = _read_json(path)
                if value.get("service") != service or value.get("command_hash") != digest:
                    continue
                try:
                    item_uid = int(value.get("uid", -1))
                    created = float(value.get("created_at", 0))
                except (TypeError, ValueError):
                    continue
                if item_uid == uid and created and now - created <= window_seconds and value.get("status") == "approved":
                    return True
            except (OSError, ValueError, json.JSONDecodeError):
                continue
        return False

    def remove(self, value: str) -> None:
        for path in (self.path(value), self.lock_path(value)):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass


class ApprovalSocketServer:
    def __init__(self, store: RequestStore, log: logging.Logger) -> None:
        self.store = store
        self.log = log
        self.path = socket_path()
        self.stop_event = threading.Event()
        self.server: socket.socket | None = None
        self.thread: threading.Thread | None = None
        try:
            self.group_id = grp.getgrnam(setting("APPROVAL_SOCKET_GROUP", "admin")).gr_gid
        except KeyError:
            self.group_id = os.getgid()

    def start(self) -> None:
        if not self.path.is_absolute():
            raise ValueError("approval socket path must be absolute")
        ensure_dir(self.path.parent, 0o755)
        try:
            if self.path.exists() or self.path.is_symlink():
                mode = self.path.lstat().st_mode
                if not stat.S_ISSOCK(mode):
                    raise RuntimeError("approval socket path is not a socket")
                self.path.unlink()
        except FileNotFoundError:
            pass
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.path))
        if os.geteuid() == 0:
            try:
                os.chown(self.path, 0, self.group_id)
            except OSError:
                pass
        try:
            socket_mode = int(setting("APPROVAL_SOCKET_MODE", "0666"), 8)
        except ValueError:
            socket_mode = 0o666
        os.chmod(self.path, socket_mode & 0o666)
        server.listen(16)
        server.settimeout(0.5)
        self.server = server
        self.thread = threading.Thread(target=self._serve, name="approval-socket", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.server is not None:
            try:
                self.server.close()
            except OSError:
                pass
        if self.thread is not None:
            self.thread.join(timeout=2)
        try:
            mode = self.path.lstat().st_mode
            if stat.S_ISSOCK(mode):
                self.path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass

    def _peer(self, connection: socket.socket) -> tuple[int, int, int]:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", raw)
        return pid, uid, gid

    def _read_message(self, connection: socket.socket) -> dict[str, Any]:
        data = b""
        while len(data) < 8192:
            chunk = connection.recv(min(4096, 8192 - len(data)))
            if not chunk:
                break
            data += chunk
            if b"\n" in chunk:
                break
        if not data or len(data) >= 8192:
            raise ValueError("approval request is too large")
        value = json.loads(data.split(b"\n", 1)[0].decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("approval request is invalid")
        return value

    def _write_message(self, connection: socket.socket, value: dict[str, Any]) -> None:
        connection.sendall((json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8"))

    def _user(self, uid: int) -> str:
        if uid == 0:
            raise PermissionError("root cannot use the command broker")
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError as exc:
            raise PermissionError("unknown local user") from exc

    def _create(self, message: dict[str, Any], uid: int) -> dict[str, Any]:
        argv = message.get("argv")
        executable = message.get("executable")
        if not isinstance(argv, list) or not argv or len(argv) > 32:
            raise ValueError("argv must contain between 1 and 32 arguments")
        if not isinstance(executable, str) or not os.path.isabs(executable):
            raise ValueError("executable must be absolute")
        values: list[str] = []
        for value in argv:
            if not isinstance(value, str) or not value or len(value) > 512 or "\x00" in value:
                raise ValueError("invalid command argument")
            values.append(value)
        pending = [item for item in self.store.pending() if int(item.get("uid", -1)) == uid]
        if len(pending) >= setting_int("APPROVAL_MAX_PENDING_PER_USER", 5, 1, 50):
            raise RuntimeError("too many pending command requests")
        display = " ".join(shlex.quote(value) for value in values)
        request = self.store.create({
            "service": "exec",
            "user": self._user(uid),
            "ip": "local",
            "uid": uid,
            "command": redact_command(display, setting_int("APPROVAL_MAX_COMMAND", 700, 100, 2000)),
            "command_hash": command_hash("\0".join(values)),
            "executable": clean_text(executable, 512),
            "cwd": clean_text(str(message.get("cwd", "")), 512),
            "argv_count": len(values),
        })
        audit("exec_request_created", request_id=request["id"], user=request["user"], command_hash=request["command_hash"])
        return {"ok": True, "id": request["id"]}

    def _wait(self, message: dict[str, Any], uid: int) -> dict[str, Any]:
        value = str(message.get("id", ""))
        request = self.store.read(value)
        if request is None or int(request.get("uid", -1)) != uid:
            raise PermissionError("request does not belong to this user")
        status_value = request.get("status")
        if status_value in {"approved", "rejected"}:
            if self.store.consume(value, {str(status_value)}) is None:
                return {"ok": False, "error": "request was already consumed"}
            return {"ok": True, "status": status_value}
        if status_value in {"pending", "expired"}:
            return {"ok": True, "status": status_value}
        return {"ok": False, "error": "request is no longer active"}

    def _handle(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(5)
            _, uid, _ = self._peer(connection)
            message = self._read_message(connection)
            action = message.get("action")
            if action == "create":
                result = self._create(message, uid)
            elif action == "wait":
                result = self._wait(message, uid)
            else:
                result = {"ok": False, "error": "unknown action"}
            self._write_message(connection, result)
        except PermissionError as exc:
            self._write_message(connection, {"ok": False, "error": str(exc)})
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            self._write_message(connection, {"ok": False, "error": clean_text(str(exc), 180)})
        except Exception as exc:
            self.log.warning("approval socket request failed: %s", type(exc).__name__)
            try:
                self._write_message(connection, {"ok": False, "error": "internal error"})
            except OSError:
                pass
        finally:
            try:
                connection.close()
            except OSError:
                pass

    def _serve(self) -> None:
        while not self.stop_event.is_set() and self.server is not None:
            try:
                connection, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._handle(connection)


class BanStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (data_dir() / "bans.json")
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        ensure_dir(self.path.parent)

    def _read(self) -> dict[str, Any]:
        try:
            value = _read_json(self.path)
            if isinstance(value.get("bans"), list):
                return value
        except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
            pass
        return {"version": 1, "bans": []}

    def _write(self, value: dict[str, Any]) -> None:
        _atomic_write(self.path, value)

    def active(self, user: str, ip: str, now: float | None = None) -> dict[str, Any] | None:
        now = time.time() if now is None else now
        user_key = normalize_identity(user)
        ip_key = normalize_identity(ip)
        with _locked(self.lock_path):
            value = self._read()
            kept = []
            found = None
            for record in value["bans"]:
                if not isinstance(record, dict) or _expiry(record) <= now:
                    continue
                kept.append(record)
                if normalize_identity(str(record.get("user", ""))) == user_key and normalize_identity(str(record.get("ip", ""))) == ip_key:
                    found = dict(record)
            if len(kept) != len(value["bans"]):
                value["bans"] = kept
                self._write(value)
            return found

    def add(self, user: str, ip: str, reason: str, duration: int) -> dict[str, Any]:
        now = time.time()
        user_key = normalize_identity(user)
        ip_key = normalize_identity(ip)
        record = {
            "user": user_key,
            "ip": ip_key,
            "reason": clean_text(reason, 160),
            "created_at": now,
            "expires_at": now + max(60, duration),
        }
        with _locked(self.lock_path):
            value = self._read()
            value["bans"] = [item for item in value["bans"] if isinstance(item, dict) and _expiry(item) > now]
            for item in value["bans"]:
                if normalize_identity(str(item.get("user", ""))) == user_key and normalize_identity(str(item.get("ip", ""))) == ip_key:
                    item["expires_at"] = max(float(item.get("expires_at", 0)), record["expires_at"])
                    item["reason"] = record["reason"]
                    record = dict(item)
                    break
            else:
                value["bans"].append(record)
            limit = setting_int("APPROVAL_MAX_BANS", 1000, 1, 1000000)
            if len(value["bans"]) > limit:
                value["bans"] = sorted(
                    value["bans"], key=lambda item: float(item.get("expires_at", 0)), reverse=True
                )[:limit]
            self._write(value)
        return record

    def remove(self, user: str | None = None, ip: str | None = None) -> int:
        user_key = normalize_identity(user or "")
        ip_key = normalize_identity(ip or "")
        with _locked(self.lock_path):
            value = self._read()
            before = len(value["bans"])
            value["bans"] = [
                item for item in value["bans"]
                if not (
                    (not user_key or normalize_identity(str(item.get("user", ""))) == user_key)
                    and (not ip_key or normalize_identity(str(item.get("ip", ""))) == ip_key)
                )
            ]
            self._write(value)
            return before - len(value["bans"])

    def active_count(self) -> int:
        now = time.time()
        with _locked(self.lock_path):
            value = self._read()
            return sum(1 for item in value["bans"] if isinstance(item, dict) and _expiry(item) > now)

    def list_active(self) -> list[dict[str, Any]]:
        now = time.time()
        with _locked(self.lock_path):
            value = self._read()
            return [dict(item) for item in value["bans"] if isinstance(item, dict) and _expiry(item) > now]


class ApprovalService:
    def __init__(self, config: Any, stop: threading.Event) -> None:
        self.config = config
        self.stop = stop
        self.log = logging.getLogger("agent.approval")
        self.store = RequestStore()
        self.bans = BanStore()
        self.admin_ids = {normalize_identity(value) for value in setting("APPROVAL_ADMIN_IDS", "").split(",") if normalize_identity(value)}
       
        self.owner_id = normalize_identity(getattr(config, "owner_id", "") or "")
        env_admins = getattr(config, "admin_ids", None) or ()
        self.admin_ids |= {normalize_identity(value) for value in env_admins if normalize_identity(value)}
        self.owner_only = bool(self.owner_id)
        self.offset_path = data_dir() / "telegram.offset"
        self.offset = self._load_offset()

    def may_decide(self, telegram_id: str) -> bool:
        sender = normalize_identity(telegram_id)
        if not sender:
            return False
        if self.owner_only:
            return sender == self.owner_id
        return sender in self.admin_ids

    def owner_only_enabled(self) -> bool:
        return self.owner_only

    def may_decide_all(self) -> bool:
        return bool(self.owner_id) if self.owner_only else bool(self.admin_ids)

    def _load_offset(self) -> int:
        try:
            return max(0, int(self.offset_path.read_text(encoding="ascii").strip()))
        except (OSError, ValueError):
            return 0

    def _save_offset(self) -> None:
        ensure_dir(self.offset_path.parent)
        fd, temporary = tempfile.mkstemp(prefix=".offset-", dir=str(self.offset_path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as stream:
                stream.write(str(self.offset) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.offset_path)
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise

    def _api(self, method: str, values: dict[str, Any], timeout: int = 25) -> Any:
        url = f"https://api.telegram.org/bot{self.config.token}/{method}"
        payload = urlencode(values).encode("utf-8")
        request = Request(url, data=payload, headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urlopen(request, timeout=timeout) as response:
            body = response.read(1048576)
        result = json.loads(body.decode("utf-8"))
        if not result.get("ok"):
            raise RuntimeError("telegram API rejected request")
        return result.get("result")

    def _message_for(self, request: dict[str, Any]) -> tuple[str, str]:
        user = html.escape(clean_text(str(request.get("user", "")), 128))
        ip = html.escape(clean_text(str(request.get("ip", "")), 128))
        service = str(request.get("service", ""))
        if service == "sshd":
            title = "SSH login request"
            detail = f"User: <code>{user}</code>\nIP: <code>{ip}</code>\nType: SSH"
        elif service == "exec":
            command = html.escape(clean_text(str(request.get("command", "")), 700))
            command_hash = html.escape(clean_text(str(request.get("command_hash", "")), 64))
            title = "Command approval request"
            detail = f"User: <code>{user}</code>\nSource: <code>agent-run</code>\nCommand: <code>{command or 'argv unavailable'}</code>\nCommand ID: <code>{command_hash}</code>"
        else:
            command = html.escape(clean_text(str(request.get("command", "")), 700))
            command_hash = html.escape(clean_text(str(request.get("command_hash", "")), 64))
            title = "sudo command request"
            detail = f"User: <code>{user}</code>\nIP: <code>{ip}</code>\nCommand: <code>{command or 'argv unavailable'}</code>\nCommand ID: <code>{command_hash}</code>"
        return title, f"<b>{title}</b>\n\n{detail}\n\nThis request is single-use."

    def _send_request(self, request: dict[str, Any]) -> bool:
        title, text = self._message_for(request)
        value = str(request["id"])
        markup = {"inline_keyboard": [[{"text": "✅ Approve", "callback_data": f"ga:a:{value}"}, {"text": "⛔ Reject", "callback_data": f"ga:r:{value}"}]]}
        try:
            self._api("sendMessage", {"chat_id": self.config.chat_id, "text": text, "parse_mode": "HTML", "reply_markup": json.dumps(markup, separators=(",", ":")), "disable_web_page_preview": "true"})
            return True
        except Exception as exc:
            self.log.warning("approval notification failed: %s", type(exc).__name__)
            return False

    def _notify_loop(self) -> None:
        while not self.stop.is_set():
            try:
                for request in self.store.pending():
                    value = str(request["id"])
                    claimed = self.store.claim_notification(value)
                    if claimed is None:
                        continue
                    if self._send_request(claimed):
                        self.store.mark_notified(value)
                    else:
                        self.store.release_notification(value)
            except Exception as exc:
                self.log.warning("approval notifier loop failed: %s", type(exc).__name__)
            self.stop.wait(1)

    def _answer(self, query: dict[str, Any], text: str, alert: bool = False) -> None:
        values = {"callback_query_id": str(query.get("id", "")), "text": clean_text(text, 180), "show_alert": "true" if alert else "false"}
        try:
            self._api("answerCallbackQuery", values, timeout=10)
        except Exception as exc:
            self.log.warning("approval callback answer failed: %s", type(exc).__name__)

    def _remove_keyboard(self, query: dict[str, Any]) -> None:
        message = query.get("message") or {}
        if "chat" not in message or "message_id" not in message:
            return
        try:
            self._api("editMessageReplyMarkup", {"chat_id": message["chat"]["id"], "message_id": message["message_id"], "reply_markup": json.dumps({"inline_keyboard": []}, separators=(",", ":"))}, timeout=10)
        except Exception as exc:
            self.log.warning("approval keyboard cleanup failed: %s", type(exc).__name__)

    def _process_callback(self, query: dict[str, Any]) -> None:
        sender = str((query.get("from") or {}).get("id", ""))
        if not self.may_decide(sender):
            audit(
                "telegram_unauthorized_decision",
                actor=clean_text(sender, 64),
                data=clean_text(str(query.get("data", "")), 100),
            )
            self._answer(query, "Only the owner can approve requests", True)
            return
        match = re.fullmatch(r"ga:([ar]):([A-Za-z0-9_-]{16,80})", str(query.get("data", "")))
        if match is None:
            self._answer(query, "Invalid request", True)
            return
        action = "approve" if match.group(1) == "a" else "reject"
        value = match.group(2)
        request = self.store.read(value)
        if request is None:
            self._answer(query, "Request expired", True)
            return
        if request.get("status") != "pending":
            self._answer(query, "This request was already processed", True)
            return
        if action == "reject" and request.get("service") == "sshd":
            try:
                self.bans.add(str(request.get("user", "")), str(request.get("ip", "")), "Telegram reject", setting_int("APPROVAL_BAN_SECONDS", DEFAULT_BAN_SECONDS, 60, 604800))
            except Exception as exc:
                self.log.error("approval ban persistence failed: %s", type(exc).__name__)
                self._answer(query, "Ban persistence failed", True)
                return
        decided = self.store.decide(value, action, sender)
        if decided is None:
            self._answer(query, "Request state changed", True)
            return
        self._remove_keyboard(query)
        self._answer(query, "Request approved" if action == "approve" else "Request rejected")
        audit("telegram_decision", request_id=value, action=action, actor=sender, service=request.get("service", ""))

    def _poll_loop(self) -> None:
        backoff = 1
        while not self.stop.is_set():
            try:
                result = self._api("getUpdates", {"offset": str(self.offset), "timeout": 20, "limit": 100}, timeout=35)
                if result:
                    for update in result:
                        update_id = int(update.get("update_id", 0))
                        self.offset = max(self.offset, update_id + 1)
                        query = update.get("callback_query")
                        if isinstance(query, dict):
                            self._process_callback(query)
                    self._save_offset()
                backoff = 1
            except Exception as exc:
                self.log.warning("approval update polling failed: %s", type(exc).__name__)
                self.stop.wait(backoff)
                backoff = min(60, backoff * 2)

    def run(self) -> None:
        if not setting_bool("APPROVAL_ENABLED", False):
            self.log.info("approval gate is disabled")
            self.stop.wait()
            return
        self.log.info("approval gate worker started")
        if not self.may_decide_all():
            self.log.error("approval gate has no authorized Telegram decision maker")
            self.stop.wait()
            return
        if self.owner_only:
            self.log.info("approval decisions restricted to owner id %s", self.owner_id)
        socket_server = ApprovalSocketServer(self.store, self.log)
        try:
            socket_server.start()
        except Exception as exc:
            self.log.error("approval socket failed: %s", type(exc).__name__)
            return
        threads = [threading.Thread(target=self._notify_loop, name="approval-notify", daemon=True), threading.Thread(target=self._poll_loop, name="approval-poll", daemon=True)]
        for thread in threads:
            thread.start()
        try:
            while not self.stop.wait(1):
                if not all(thread.is_alive() for thread in threads):
                    self.log.error("approval worker thread exited")
                    return
        finally:
            socket_server.stop()
            for thread in threads:
                thread.join(timeout=2)


def bypass_path() -> Path:
    return state_dir() / "emergency-bypass"


def bypass_active() -> bool:
    path = bypass_path()
    try:
        value = _read_json(path)
        return float(value.get("expires_at", 0)) > time.time()
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
        return False


def set_bypass(minutes: int) -> int:
    minutes = max(1, min(1440, minutes))
    expires = int(time.time() + minutes * 60)
    ensure_dir(state_dir())
    _atomic_write(bypass_path(), {"expires_at": expires}, 0o600)
    audit("emergency_bypass_enabled", minutes=minutes)
    return expires


def clear_bypass() -> None:
    try:
        bypass_path().unlink()
    except FileNotFoundError:
        pass
    audit("emergency_bypass_disabled")


def status() -> dict[str, Any]:
    return {"enabled": setting_bool("APPROVAL_ENABLED", False), "pending": len(RequestStore().pending()), "bans": BanStore().active_count(), "bypass": bypass_active()}
