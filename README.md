🏗️ Architecture

"alertbot" is built around a lightweight, fault-tolerant monitoring core designed to keep security alerts reliable, isolated, and noise-free. 🛡️

---

⚙️ Process Model

The application starts as a single daemon process:

python3 -m alertbot

The main process creates:

- ⚙️ One shared "Config"
- 📡 One Telegram sender
- 🛑 One global "threading.Event" for shutdown

Each monitor runs independently in its own daemon thread:

run(config, telegram, stop)

Monitors never communicate directly with each other.
All notifications flow through the shared Telegram sender.

                    🛡️ alertbot daemon
                           │
          ┌────────────────┼────────────────┐
          │                │                │
       🔐 SSH          📜 Journal       📁 Filesystem
       Monitor          Monitor           Monitor
          │                │                │
          └────────────────┼────────────────┘
                           ▼
                  📡 Telegram Sender
                  ┌──────────────────┐
                  │ 🔁 Deduplication │
                  │ ⏱️ Cooldowns     │
                  │ 🚦 Rate Limiting │
                  │ 🔄 429 Backoff   │
                  └────────┬─────────┘
                           ▼
                    ✈️ Telegram API

🛑 Graceful Shutdown

"SIGTERM" and "SIGINT" set the shared shutdown event.

The main process checks monitor health every 2 seconds.

If a monitor thread unexpectedly dies, the daemon exits so "systemd" can restart the entire monitoring group.

«💡 Fail the whole service, not silently lose a security sensor.»

---

📡 Telegram Notification Layer

"alertbot/telegram.py"

All notifications pass through a single thread-safe sender:

send(key, text, cooldown=None)

Example notification buckets:

ssh-login:<ip>
file:Changed:/etc/passwd

✨ Features

Feature| Purpose
🔁 Deduplication| Prevent repeated alerts
⏱️ Per-key cooldown| Suppress notification spam
🚦 Global rate limit| 150ms spacing between requests
🔄 429 handling| Respects Telegram "Retry-After"
🔒 Thread safety| Shared state protected by a lock
🧱 Failure isolation| Telegram failures never kill monitors

«🛡️ A Telegram outage should never become a monitoring outage.»

---

🔍 Security Monitors

🧩 Monitor| 📡 Source| 🚨 Detection
🔐 "ssh.py"| journald| Login activity, failures, sudo & escalation
📜 "journal.py"| systemd journal| Service failures, crashes & restarts
📁 "filesystem.py"| SHA-256 scans| Persistent file modifications
🚫 "fail2ban.py"| Fail2Ban logs| Bans & security events
🛡️ "crowdsec.py"| CrowdSec CLI| IP decisions & bans
☠️ "dangerous_commands.py"| Linux Audit| Destructive commands by non-root users

---

🔐 SSH Monitoring

The SSH monitor watches journald events from:

_COMM=sshd
_COMM=sudo

It detects:

- ✅ Successful logins
- ❌ Authentication failures
- 📈 Repeated failure escalation
- 🔑 Sudo activity

Instead of blindly alerting on every failed attempt, repeated failures can be grouped into an escalation event.

---

📜 Service Monitoring

"journal.py" follows configured systemd units in real time.

It watches for:

- 💥 Service failures
- 💀 Crashes
- 🛑 Unexpected stops
- 🔄 Restarts
- 🐕 Watchdog failures

Each watched unit runs independently.

---

📁 Filesystem Monitoring

"filesystem.py" periodically calculates SHA-256 hashes across configured paths.

A single changed snapshot is not immediately considered an alert.

The same:

(event, path)

must appear in two consecutive scans.

💡 Why?

This filters out noise caused by:

- 📝 Partial writes
- 📦 Temporary files
- 💾 Backup operations
- 🔄 Atomic file replacement
- ⚡ Race conditions

A maximum of 30 filesystem alerts per scan prevents a large modification from flooding Telegram.

«🎯 Signal over noise.»

---

🚫 Fail2Ban Monitoring

"fail2ban.py" follows:

/var/log/fail2ban.log

It tracks the log inode, allowing monitoring to survive log rotation without losing its position.

---

🛡️ CrowdSec Monitoring

"crowdsec.py" periodically queries:

cscli decisions list -o json
[10/4/26 11:04 PM] 人名用・D マーシャル: Decisions are deduplicated by IP.

This means the same ban won't repeatedly generate identical alerts.

---

☠️ Dangerous Command Detection

"dangerous_commands.py" monitors:

/var/log/audit/audit.log

The monitor correlates Linux Audit events:

        🔎 SYSCALL
            │
            │ audit event ID
            ▼
        🧩 EXECVE
            │
            ├── Command
            └── Arguments

🧠 Why correlation matters

"EXECVE" contains the executed command and arguments, but the required user attribution comes from the matching "SYSCALL" event.

The monitor therefore:

1. 🔎 Extracts the audit event ID
2. 👤 Buffers the associated UID
3. 🔗 Correlates it with "EXECVE"
4. 🚨 Alerts only when the command can be attributed to a non-root user

This avoids incorrectly blaming or reporting commands without reliable user attribution.

---

🔐 Approval Subsystem

Located under:

alertbot/
└── approval/
    ├── service.py
    └── helper.py

🖥️ "service.py"

The daemon-side approval service provides:

- 📋 "RequestStore"
- 🚫 "BanStore"
- 🔌 "ApprovalSocketServer"
- 🧠 "ApprovalService"
- ⚙️ Configuration & path management
- 💾 Atomic JSON writes
- 🔒 File locking
- 📝 Audit logging

🚪 "helper.py"

The gate-side helper integrates with PAM/sudo hooks.

Flow:

👤 User
   │
   ▼
🚪 Approval Helper
   │
   ▼
📋 Create Request
   │
   ▼
🔌 UNIX Socket
   │
   ▼
👨‍💻 Administrator
   │
   ├── ✅ Approve
   └── ❌ Deny
   │
   ▼
🚦 Execution Result

---

🧱 Fail-Closed Security

The approval subsystem is intentionally fail-closed.

If the approval store or UNIX socket cannot be reached:

❌ Request denied

rather than:

⚠️ Request allowed

«🔐 Security controls should fail closed, never become an accidental privilege bypass.»

---

🔒 Host Security Boundaries

📂 Resource| 🔢 Mode| 🎯 Purpose
"/opt/agent-security-alert"| "0755"| Application files
"/etc/agent/security-alert.env"| "0600"| Root-only configuration
"/var/lib/agent-security-alert"| "0700"| Persistent state
"/run/agent-security-alert"| "0700"| Runtime state
Approval socket| "0600"| Restricted IPC

The systemd unit additionally applies:

UMask=0077
CapabilityBoundingSet=

The service runs without retained Linux capabilities and is restricted to the required address families:

AF_UNIX
AF_INET
AF_INET6

---

🧠 Design Principles

🧩 Isolate Failures

A broken monitor should never silently disable the others.

📡 Centralize Notifications

Every Telegram notification goes through one controlled sender.

🎯 Reduce Noise

Cooldowns, deduplication, escalation logic, and the two-scan filesystem rule keep alerts meaningful.

🔐 Fail Closed

Approval failures result in denial rather than accidental permission.

👤 Preserve Attribution

Audit events are correlated before dangerous-command alerts are generated.

🔄 Let "systemd" Recover

If the daemon becomes unhealthy, it exits and lets the service manager restart it.

---

🛡️ Built for Signal, Not Noise.

Independent monitors. Centralized alerts. Fail-closed security.

⭐ If "alertbot" is useful to you, consider giving the repository a Star.