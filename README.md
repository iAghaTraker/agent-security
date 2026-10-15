# Agent Security

A lightweight Linux server monitoring daemon that sends security alerts to Telegram. It brings together SSH and sudo activity monitoring, systemd service events, filesystem integrity snapshots, and optional integrations with Fail2Ban, CrowdSec, and Linux Audit.

> **Security notice:** This project monitors security-relevant events and includes an access-approval subsystem. Monitoring is not a substitute for hardening, backups, access controls, or incident response. Review the code, test it in a disposable environment, and verify every enabled monitor and approval integration before relying on it on a production host.

## What it does

- **SSH and sudo activity:** Watches relevant system journal events and reports detected logins, authentication failures, repeated failures, and sudo activity.
- **systemd services:** Watches configured units and reports matching service events and configured journal keywords.
- **Filesystem integrity:** Calculates SHA-256 snapshots for configured paths and reports detected additions, changes, and deletions. Consecutive-scan confirmation can reduce transient noise.
- **Fail2Ban:** Reads the configured Fail2Ban log and reports detected security events.
- **CrowdSec:** Queries CrowdSec decisions through `cscli` when CrowdSec is installed and configured.
- **Dangerous-command detection:** Reads Linux Audit events and correlates execution records to attribute selected commands to a user.
- **Telegram notifications:** Centralizes notifications and applies deduplication, cooldowns, rate limiting, and handling for Telegram rate-limit responses.
- **Approval subsystem:** Includes a daemon-side request service and helper intended for integration with a privileged access workflow. This component is security-sensitive and must be independently reviewed and tested before use.

Some monitors require host tools, suitable permissions, configured logs, or services that are not installed by this project. A monitor being present in the code does not mean its host-side prerequisites have been configured automatically.

## Project status

The project is under active hardening. Before using it on a production host:

- Run the automated test suite and static checks.
- Verify socket ownership and permissions, request limits, and concurrent approval behavior.
- Verify that monitor errors are visible and do not silently drop important events.
- Confirm that the systemd sandbox permits only the paths the service actually needs.
- Test installation, restart, upgrade, and removal in a disposable Linux environment.
- Review the license before redistributing or publishing modifications.

Do not treat a successful import or syntax compilation as evidence that the security controls work correctly.

## Requirements

- Linux with systemd and systemd-journald
- Python 3.10 or newer
- A Telegram bot token and destination chat ID
- Root privileges for the supplied system service and for reading protected host logs
- Optional integrations, depending on the monitors you enable:
  - Fail2Ban and access to its configured log
  - CrowdSec and the `cscli` command
  - Linux Audit (`auditd`) and access to its audit log
  - `journalctl` for journal-based monitoring

The Python package has no third-party runtime dependencies declared in `pyproject.toml`. Optional host tools are separate system requirements.

## Installation

Use a disposable Linux machine or VM for the first installation. Do not enable privileged approval or PAM-related integration on a production host until it has been separately reviewed and tested.

### 1. Get the source

```bash
git clone https://github.com/iAghaTraker/agent-security.git
cd agent-security
```

### 2. Create the configuration file

```bash
sudo install -d -m 0750 /etc/agent
sudo install -m 0600 deploy/example.env /etc/agent/security-alert.env
sudoedit /etc/agent/security-alert.env
```

Set at least these values:

```dotenv
TELEGRAM_BOT_TOKEN=replace_with_your_bot_token
TELEGRAM_CHAT_ID=replace_with_your_chat_id
```

Do not commit real credentials, send them in issue reports, or include them in screenshots. Keep the configuration file readable only by the service's authorized administrator.

### 3. Review monitor settings

The example configuration lists the supported environment variables and their defaults. Review watched paths, service names, log paths, cooldowns, and disabled monitors before starting the daemon.

To disable specific monitors, set `AGENT_DISABLE_MONITORS` to a comma-separated list of monitor keys. Supported keys are `ssh`, `journal`, `filesystem`, `crowdsec`, `fail2ban`, and `commands`.

For example:

```dotenv
AGENT_DISABLE_MONITORS=crowdsec,fail2ban
```

Any monitor not listed remains enabled. Disable monitors whose prerequisites are absent or which you have not yet validated.

### 4. Install the systemd service

The deployment script installs the package under `/opt/agent-security-alert`, installs the systemd unit, reloads systemd, and attempts to restart the service. Review the script and unit before running them.

```bash
sudo bash deploy/install.sh
```

The script expects the configuration file at `/etc/agent/security-alert.env`. If it is missing or incomplete, the service may fail to start.

### 5. Check service status and logs

```bash
sudo systemctl status agent-security-alert.service
sudo journalctl -u agent-security-alert.service -n 100 --no-pager
sudo tail -n 100 /var/log/agent-security.log
```

The configured application log path must be writable under the systemd unit's filesystem restrictions. If the service cannot start or write logs, inspect the service journal and reconcile `AGENT_LOG_PATH` with the unit's permitted write paths before proceeding.

### 6. Verify delivery

Generate only harmless test events in your disposable environment. Confirm that:

- The daemon starts and stays active.
- Telegram receives the expected alert.
- Repeated events are handled according to the configured cooldown.
- A stopped optional integration produces a visible, understandable status or error.
- The service can restart cleanly after a controlled failure.

Do not test destructive commands, access denial, or PAM behavior on a production machine.

## Configuration reference

The authoritative list of configuration defaults is in `alertbot/config.py` and `deploy/example.env`. The following are the primary settings.

| Variable | Purpose |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Required Telegram bot token |
| `TELEGRAM_CHAT_ID` | Required destination chat ID |
| `AGENT_OWNER_ID` | Telegram user ID designated as the approval owner |
| `AGENT_ADMIN_IDS` | Comma-separated administrator IDs used when no owner ID is set |
| `AGENT_DISABLE_MONITORS` | Comma-separated monitor keys to disable |
| `AGENT_COOLDOWN_SECONDS` | Global alert cooldown |
| `AGENT_LOG_PATH` | Application log path |
| `AGENT_SERVICES` | Comma-separated systemd units to monitor |
| `AGENT_JOURNAL_KEYWORDS` | Comma-separated keywords used by journal monitoring |
| `AGENT_WATCH_ROOTS` | Comma-separated filesystem roots to scan |
| `AGENT_SKIP_NAMES` | Comma-separated directory or file names to skip |
| `AGENT_FILE_SCAN_SECONDS` | Filesystem scan interval |
| `AGENT_FILE_MAX_BYTES` | Maximum file size included in a hash scan |
| `AGENT_FILE_MAX_EVENTS` | Maximum filesystem alerts per scan |
| `AGENT_FILE_CONFIRM_SCANS` | Consecutive observations required before a filesystem alert |
| `AGENT_SUDO_AUDIT_LOG` | Path used to archive matched sudo journal lines |
| `AGENT_FAIL2BAN_LOG` | Fail2Ban log path |
| `AGENT_CROWDSEC_SCAN_SECONDS` | CrowdSec polling interval |
| `AGENT_AUDIT_LOG` | Linux Audit log path |
| `AGENT_AUDIT_KEY` | Audit rule key used to identify relevant execution events |
| `AGENT_DANGEROUS_BINARIES` | Comma-separated executable names to watch |
| `AGENT_COMMAND_COOLDOWN_SECONDS` | Dangerous-command alert cooldown |
| `AGENT_APPROVAL_MATCH_WINDOW` | Time window used to correlate approvals with commands |
| `AGENT_COMMAND_HISTORY_SIZE` | Maximum in-memory command history size |

Approval-specific settings are read by the approval subsystem and may use `/etc/agent/approval.conf`. Review `alertbot/approval/service.py` and `alertbot/approval/helper.py` to understand the effective configuration and trust boundaries. Do not assume every `AGENT_*` variable also configures the approval subsystem.

## Monitor behavior

### SSH and sudo

The SSH monitor consumes relevant journal output and looks for authentication and sudo events. Log formats vary across distributions and versions; verify the patterns against the actual journal on the target host. Command text can contain secrets, so redaction and log-access controls must be validated.

### systemd journal

The journal monitor follows the configured systemd units and checks events against configured keywords. It does not replace service health checks or application-level monitoring.

### Filesystem integrity

The filesystem monitor builds snapshots of configured paths using SHA-256. It can require multiple consecutive observations before reporting a change. The scan is a change detector, not a cryptographically protected baseline: an attacker with sufficient privileges may alter the monitored files and the monitoring process itself.

Large scan roots can increase CPU and disk I/O. Avoid broad paths unless their cost and exclusions have been reviewed.

### Fail2Ban and CrowdSec

These integrations depend on the host's installed service, log format, command availability, and permissions. Verify that the configured log path and CLI output match the installed versions.

### Linux Audit and dangerous commands

Dangerous-command detection depends on Linux Audit records being generated and retained with the expected configuration. Installing this Python package does not by itself guarantee that suitable audit rules are enabled. Validate the audit rules, event correlation, and user attribution on the target distribution.

### Approval subsystem

The approval subsystem is a privileged security boundary, not merely a notification feature. Before enabling it, review:

- Socket path, owner, group, and permissions
- Request authentication, validation, expiry, and replay handling
- Per-user and global resource limits
- Concurrent decisions and state transitions
- Audit log integrity and permissions
- Behavior when the daemon, socket, store, or Telegram connection is unavailable
- PAM or sudo integration and its exact fail-open/fail-closed behavior

Do not infer that a fail-closed design claim has been proven until these scenarios are covered by automated tests and integration tests.

## Architecture

The daemon starts configured monitors in separate worker threads and shares a central Telegram sender. A shutdown event is used for graceful termination. The service manager can restart the process when the daemon exits unexpectedly.

Key source files:

| Path | Responsibility |
|---|---|
| `alertbot/__main__.py` | Process startup and monitor lifecycle |
| `alertbot/config.py` | Environment-based monitor configuration |
| `alertbot/telegram.py` | Telegram delivery and notification controls |
| `alertbot/monitors/ssh.py` | SSH and sudo journal monitoring |
| `alertbot/monitors/journal.py` | systemd unit event monitoring |
| `alertbot/monitors/filesystem.py` | Filesystem snapshots |
| `alertbot/monitors/fail2ban.py` | Fail2Ban log monitoring |
| `alertbot/monitors/crowdsec.py` | CrowdSec decision monitoring |
| `alertbot/monitors/dangerous_commands.py` | Linux Audit command detection |
| `alertbot/approval/service.py` | Approval requests, state, socket server, and audit records |
| `alertbot/approval/helper.py` | Approval-side helper integration |
| `deploy/agent-security-alert.service` | systemd service definition |
| `deploy/install.sh` | Deployment script |
| `deploy/example.env` | Example environment configuration |
| `docs/architecture.md` | Architecture notes |

## Development and validation

Run checks from the repository root with the same Python version you plan to support.

```bash
python3 -m compileall -q alertbot
python3 -m pytest -q
```

A test command that reports no tests collected is not a successful test suite. Add and run automated tests for monitor parsing, redaction, Telegram failure handling, approval authorization, socket permissions, request limits, concurrent decisions, and fail-closed behavior.

For a more complete local review, also inspect the deployment script and systemd unit, run static analysis if configured, and test against controlled sample logs. Do not use real credentials or production logs in public test fixtures.

## Troubleshooting

### The service does not start

```bash
sudo systemctl status agent-security-alert.service
sudo journalctl -u agent-security-alert.service -n 100 --no-pager
```

Check the environment file, Python version, permissions, import errors, and any missing host utilities.

### Telegram messages do not arrive

Check the bot token, destination chat ID, bot membership and permissions, network connectivity, and the service logs. Never paste the bot token into a public issue.

### A monitor reports no events

Check that its source service is installed and running, that its configured path exists, that the log format matches the parser, and that the service can read the source. Absence of alerts is not proof that the host is safe.

### Filesystem scanning is slow

Narrow `AGENT_WATCH_ROOTS`, exclude high-churn directories with `AGENT_SKIP_NAMES`, and review the scan interval and maximum file size.

## Security reporting

Do not publish exploitable details or credentials in public issues. Until a dedicated private reporting channel is configured, contact the repository owner through a private channel listed on the owner's GitHub profile.

## License

This repository currently includes the `iAghaTraker Proprietary License 1.0`, which is not an OSI-approved open-source license. It restricts redistribution and third-party access. Read [`LICENSE`](LICENSE) before using, modifying, or sharing the software. Do not assume that a public GitHub repository grants permission to fork, redistribute, or use the code in another product.

## Contributing

Before proposing changes, run the available checks and include reproducible steps and test results. Security-sensitive changes should include tests for both expected behavior and failure cases. Do not submit secrets, production logs containing personal data, or unredacted credentials.

---

Agent Security is intended to make important host events easier to notice. It should be deployed only after its behavior, permissions, and limitations have been validated in the target environment.
