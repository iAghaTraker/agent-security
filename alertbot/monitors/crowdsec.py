import json
import logging
import subprocess


def run(config, telegram, stop):
    log = logging.getLogger(__name__)
    seen = set()
    while not stop.wait(config.crowdsec_scan_seconds):
        try:
            raw = subprocess.check_output(["cscli", "decisions", "list", "-o", "json"], text=True, stderr=subprocess.DEVNULL)
            decisions = json.loads(raw or "[]")
            if isinstance(decisions, dict): decisions = decisions.get("decisions", [])
            for decision in decisions:
                ip = decision.get("value") or decision.get("ip")
                if not ip or ip in seen: continue
                seen.add(ip)
                reason = decision.get("scenario", "CrowdSec decision")
                telegram.send(f"crowdsec:{ip}", f"🚫 CrowdSec Ban\n\nIP:\n{ip}\n\nReason:\n{reason}", 60)
        except FileNotFoundError: log.warning("cscli is not installed")
        except Exception: log.exception("CrowdSec monitor failed")
