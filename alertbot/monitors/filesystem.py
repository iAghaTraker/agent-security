import hashlib
import logging
import os
from pathlib import Path

DEFAULT_ROOTS = ("/etc/nginx", "/etc/ssh", "/etc", "/opt")
DEFAULT_SKIP = ("node_modules", ".next", "venv", "__pycache__", ".git", "backups")


def _release_id():
    try:
        return str(Path("/opt/path/to").resolve())
    except OSError:
        return "unavailable"


def _scan(root, skip, max_bytes, result, onerror):
    walker = os.walk(root, onerror=onerror)
    for directory, _, files in walker:
        files[:] = [name for name in files if name not in skip]
        if any(part in skip for part in directory.split(os.sep)):
            continue
        for name in files:
            path = os.path.join(directory, name)
            try:
                metadata = os.stat(path)
                if metadata.st_size > max_bytes:
                    continue
                digest = hashlib.sha256()
                with open(path, "rb") as stream:
                    for chunk in iter(lambda: stream.read(65536), b""):
                        digest.update(chunk)
                result[path] = (metadata.st_mtime_ns, digest.hexdigest())
            except OSError:
                onerror(None)


def snapshot(config):
    roots = getattr(config, "watch_roots", None) or DEFAULT_ROOTS
    skip = frozenset(getattr(config, "skip_names", None) or DEFAULT_SKIP)
    max_bytes = getattr(config, "file_max_bytes", 10_000_000)
    result = {}
    errors = 0

    def onerror(error):
        nonlocal errors
        errors += 1

    for root in roots:
        try:
            _scan(root, skip, max_bytes, result, onerror)
        except OSError:
            errors += 1

    if errors:
        return None, _release_id(), errors
    return result, _release_id(), errors


def _changes(previous, current):
    changes = []
    for path in sorted(set(previous) | set(current)):
        if path not in previous:
            changes.append(("File Added", path))
        elif path not in current:
            changes.append(("File Deleted", path))
        elif previous[path] != current[path]:
            changes.append(("File Changed", path))
    return changes


def run(config, telegram, stop):
    log = logging.getLogger(__name__)
    confirm_scans = max(1, getattr(config, "file_confirm_scans", 2))
    max_events = max(1, getattr(config, "file_max_events_per_scan", 30))
    previous, release, _ = snapshot(config)
    pending = {}
    last_error_count = 0
    while not stop.wait(config.file_scan_seconds):
        try:
            current, current_release, errors = snapshot(config)
            if current is None:
                if errors != last_error_count:
                    log.warning("file monitor scan incomplete; errors=%s comparison skipped", errors)
                last_error_count = errors
                continue
            last_error_count = 0
            if previous is None or current_release != release:
                previous = current
                release = current_release
                pending.clear()
                continue
            observed = _changes(previous, current)
            next_pending = {}
            sent = 0
            for event, path in observed:
                key = (event, path)
                count = pending.get(key, 0) + 1
                next_pending[key] = count
                if count < confirm_scans or sent >= max_events:
                    continue
                telegram.send(f"file:{event}:{path}", f"🚨 Security Alert\n\nType:\n{event}\n\nPath:\n{path}", 300)
                sent += 1
            if len(observed) > sent and sent >= max_events:
                telegram.send(
                    "file:summary",
                    f"🚨 Security Alert\n\nType:\nFile event limit reached\n\n"
                    f"Observed changes:\n{len(observed)}",
                    300,
                )
            pending = next_pending
            previous = current
        except Exception:
            log.exception("File monitor failed")
