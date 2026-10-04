import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


class Telegram:
    def __init__(self, config):
        self.config = config
        self.log = logging.getLogger(__name__)
        self.last_sent = {}
        self.retry_at = {}
        self.lock = threading.Lock()
        self.last_send_at = 0.0

    def send(self, key, text, cooldown=None):
        if cooldown is None:
            cooldown = self.config.cooldown_seconds
        with self.lock:
            now = time.monotonic()
            if now - self.last_sent.get(key, 0) < cooldown or now < self.retry_at.get(key, 0):
                return False
            wait = 0.15 - (now - self.last_send_at)
            if wait > 0:
                time.sleep(wait)
            payload = urllib.parse.urlencode({"chat_id": self.config.chat_id, "text": text}).encode()
            url = f"https://api.telegram.org/bot{self.config.token}/sendMessage"
            try:
                request = urllib.request.Request(url, payload, {"Content-Type": "application/x-www-form-urlencoded"})
                with urllib.request.urlopen(request, timeout=5) as response:
                    if 200 <= response.status < 300:
                        self.last_sent[key] = time.monotonic()
                        self.last_send_at = self.last_sent[key]
                        self.retry_at.pop(key, None)
                        self.log.info("Telegram alert sent to configured chat (event=%s)", key)
                        return True
                    self.log.error("Telegram API returned HTTP %s", response.status)
                    self.retry_at[key] = time.monotonic() + 5
            except urllib.error.HTTPError as exc:
                retry = 5
                if exc.code == 429:
                    try:
                        retry = min(60, max(5, int(exc.headers.get("Retry-After", "5"))))
                    except (TypeError, ValueError):
                        retry = 5
                self.retry_at[key] = time.monotonic() + retry
                self.log.error("Telegram API returned HTTP %s", exc.code)
            except Exception as exc:
                self.retry_at[key] = time.monotonic() + 5
                self.log.error("Telegram alert failed: %s", type(exc).__name__)
            return False
