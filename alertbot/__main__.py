import logging
import signal
import threading

from .approval.service import ApprovalService
from .config import Config
from .monitors import (
    crowdsec,
    dangerous_commands,
    fail2ban,
    filesystem,
    journal,
    ssh,
)
from .telegram import Telegram

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"

# Config key -> monitor module. Anything listed in AGENT_DISABLE_MONITORS is
# skipped entirely, so it produces no output at all.
MONITOR_MODULES = {
    "ssh": ssh,
    "journal": journal,
    "filesystem": filesystem,
    "crowdsec": crowdsec,
    "fail2ban": fail2ban,
    "commands": dangerous_commands,
}


def build_monitors(config):
    return [
        module
        for name, module in MONITOR_MODULES.items()
        if config.monitor_enabled(name)
    ]


def main():
    config = Config.from_env()
    logging.basicConfig(filename=config.log_path, level=logging.INFO, format=LOG_FORMAT)
    log = logging.getLogger("agent")
    telegram = Telegram(config)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    monitors = build_monitors(config)
    disabled = sorted(set(MONITOR_MODULES) - {m.__name__.rsplit(".", 1)[-1] for m in monitors})
    log.info("starting; monitors=%s", [m.__name__.rsplit(".", 1)[-1] for m in monitors])
    if disabled:
        log.info("disabled by config: %s", ", ".join(disabled))

    threads = [
        threading.Thread(target=module.run, args=(config, telegram, stop), daemon=True)
        for module in monitors
    ]
    threads.append(
        threading.Thread(
            target=ApprovalService(config, stop).run, name="approval", daemon=True
        )
    )
    for thread in threads:
        thread.start()
    while not stop.wait(2):
        if not all(thread.is_alive() for thread in threads):
            log.error("a worker thread exited; shutting down for systemd restart")
            break


if __name__ == "__main__":
    main()
