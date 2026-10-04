#!/usr/bin/env bash
# Deploy agent-security to /opt/agent-security-alert on the target host.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${TARGET_DIR:-/opt/agent-security-alert}"
SERVICE_FILE="${SERVICE_FILE:-/etc/systemd/system/agent-security-alert.service}"

if [[ $EUID -ne 0 ]]; then
    echo "run as root: sudo $0" >&2
    exit 1
fi

echo "-> syncing package to ${TARGET_DIR}"
install -d -m 0755 "${TARGET_DIR}"
rm -rf "${TARGET_DIR}/alertbot"
cp -r "${REPO_DIR}/alertbot" "${TARGET_DIR}/alertbot"
find "${TARGET_DIR}/alertbot" -name '__pycache__' -type d -prune -exec rm -rf {} +

echo "==> verifying imports"
cd "${TARGET_DIR}"
python3 -c 'import alertbot.__main__' >/dev/null

if [[ -f /etc/agent/security-alert.env ]]; then
    echo "-> keeping existing /etc/agent/security-alert.env"
else
    echo "-> WARNING: /etc/agent/security-alert.env missing — service will fail to start"
    echo "    create it from deploy/example.env and set TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID"
fi

echo "-> installing systemd unit"
install -m 0644 "${REPO_DIR}/deploy/agent-security-alert.service" "${SERVICE_FILE}"
systemctl daemon-reload

echo "-> restarting service"
systemctl restart agent-security-alert.service
sleep 2
systemctl --no-pager status agent-security-alert.service
