import logging
import subprocess
import threading

from ..config import DEFAULT_SERVICES


def _watch(service, telegram, stop, keywords, cooldown):
    log = logging.getLogger(__name__)
    command = ["journalctl", "-f", "-n", "0", "-o", "cat", "-u", service]
    process = None
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        while not stop.is_set():
            line = process.stdout.readline()
            if not line:
                if process.poll() is not None:
                    break
                continue
            if any(word in line.lower() for word in keywords):
                telegram.send(
                    f"systemd:{service}:{line.strip()[:120]}",
                    f"🚨 Security Alert\n\nType:\nSystemd Service Event\n\n"
                    f"Service:\n{service}\n\nEvent:\n{line.strip()[:800]}",
                    cooldown,
                )
    except Exception:
        log.exception("Journal monitor failed for %s", service)
    finally:
        if process is not None:
            try:
                process.kill()
            except Exception:
                pass


def run(config, telegram, stop):
    services = getattr(config, "services", None) or DEFAULT_SERVICES
    keywords = getattr(config, "journal_keywords", None) or (
        "failed",
        "crash",
        "stopped",
        "restart",
        "watchdog",
    )
    cooldown = getattr(config, "journal_cooldown_seconds", 300)
    threads = [
        threading.Thread(
            target=_watch,
            args=(service, telegram, stop, keywords, cooldown),
            daemon=True,
        )
        for service in services
    ]
    for thread in threads:
        thread.start()
    while not stop.wait(5):
        pass
