# 🛡️ AGENT SECURITY

<p align="center">
  <strong>YOUR SERVER. YOUR RULES. ZERO SILENT FAILURES.</strong>
</p>

<p align="center">
  A security monitoring daemon for Linux servers, with real-time Telegram alerts and a fail-closed approval gate.
</p>

<p align="center">
  <a href="https://github.com/iAghaTraker/agent-security/stargazers"><img src="https://img.shields.io/github/stars/iAghaTraker/agent-security?style=for-the-badge&color=F5C542&label=STARS" alt="GitHub Stars"></a>
  <a href="https://github.com/iAghaTraker/agent-security/network/members"><img src="https://img.shields.io/github/forks/iAghaTraker/agent-security?style=for-the-badge&color=8B949E&label=FORKS" alt="GitHub Forks"></a>
  <a href="https://github.com/iAghaTraker/agent-security/issues"><img src="https://img.shields.io/github/issues/iAghaTraker/agent-security?style=for-the-badge&color=E3A857&label=ISSUES" alt="GitHub Issues"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/LICENSE-SEE_REPOSITORY-30363D?style=for-the-badge" alt="License"></a>
</p>

<p align="center">
  <a href="#-why-agent-security">Why Agent Security</a> •
  <a href="#-security-monitoring">Monitoring</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-security-by-design">Security</a> •
  <a href="#-getting-started">Getting Started</a>
</p>

---

## ⚡ Security Should Never Fail Silently.

Your server doesn't always announce when something goes wrong.

A failed SSH login. An unexpected service crash. A critical file that suddenly changes. A dangerous command executed without the right authorization.

**Agent Security brings these events into one controlled monitoring system — and sends actionable alerts straight to Telegram.**

No sprawling dashboard. No unnecessary infrastructure. Just focused server monitoring, centralized notifications, and security controls designed to fail closed.

```text
┌──────────────────────────────────────────────────┐
│                  AGENT SECURITY                  │
│                                                  │
│   SSH  ───────────────┐                           │
│   SYSTEMD ────────────┤                           │
│   FILESYSTEM ─────────┤                           │
│   FAIL2BAN ───────────┼──► EVENT PROCESSING       │
│   CROWDSEC ───────────┤          │               │
│   LINUX AUDIT ────────┘          ▼               │
│                          ALERT CONTROL            │
│                     Deduplication • Cooldowns     │
│                     Rate Limits • Retry Handling  │
│                                  │               │
│                                  ▼               │
│                             TELEGRAM              │
└──────────────────────────────────────────────────┘
```

## 🔥 Security Monitoring

| Module | What it watches |
|---|---|
| 🔐 SSH | Successful logins, authentication failures, escalation patterns and sudo activity |
| ⚙️ Systemd | Service failures, crashes, unexpected stops, restarts and watchdog failures |
| 📁 Filesystem | SHA-256-based detection of persistent file changes |
| 🚫 Fail2Ban | Ban events and security activity from Fail2Ban logs |
| 🛡️ CrowdSec | Security decisions and IP bans |
| ☠️ Linux Audit | Dangerous command execution with user attribution |

Each monitoring component has a focused responsibility. Events flow through a shared notification layer instead of competing to send messages independently.

## 🧱 Built Around Failure Isolation

### 📡 One notification pipeline

All alerts pass through a thread-safe Telegram sender.

- Duplicate event suppression
- Per-event cooldowns
- Global request rate limiting
- HTTP 429 handling with retry delays
- Failure isolation between Telegram delivery and monitoring

**A Telegram outage should never become a monitoring outage.**

### 🔍 Noise reduction that matters

Security monitoring is useless if every routine event becomes another notification to ignore.

Agent Security uses event deduplication, escalation grouping, cooldowns and consecutive filesystem scans to reduce unnecessary noise.

Filesystem changes must persist across consecutive scans before being treated as alerts, helping filter transient writes and atomic file replacements.

### 🔄 Recovery without silent degradation

The daemon monitors its worker threads and handles graceful shutdown signals.

If a monitoring thread unexpectedly dies, the daemon exits rather than silently running with a missing sensor, allowing `systemd` to restart the service.

---

## 🔐 Fail-Closed Approval Gate

**Authorization must never become optional just because a security component is unavailable.**

The approval subsystem integrates with PAM/sudo hooks and communicates with the daemon through a restricted UNIX socket.

```text
        USER REQUEST
             │
             ▼
      APPROVAL HELPER
             │
             ▼
       REQUEST STORE
             │
             ▼
       UNIX SOCKET
             │
             ▼
    ADMINISTRATOR REVIEW
         ┌───┴───┐
         ▼       ▼
      APPROVE   DENY
         │       │
         └───┬───┘
             ▼
      EXECUTION RESULT
```

The subsystem includes request and ban stores, file locking, atomic JSON writes and audit logging.

### The rule is simple.

If the approval store or communication socket is unavailable, the request is denied rather than automatically allowed.

**Fail closed. Never fail open by accident.**

---

## 🛡️ Security by Design

Security isn't just another notification category. It is part of how the application operates.

- **Restricted permissions:** sensitive configuration and runtime state use restrictive filesystem permissions.
- **UNIX socket isolation:** local approval communication is protected by socket permissions.
- **Minimal Linux capabilities:** the systemd service is configured without retained Linux capabilities.
- **Reliable attribution:** Linux Audit events are correlated before generating non-root dangerous-command alerts.
- **Atomic state updates:** approval data uses atomic writes and file locking.
- **Controlled shutdown:** SIGTERM and SIGINT trigger graceful shutdown handling.
- **Bounded alert volume:** filesystem notifications have a per-scan limit.

These controls reduce unnecessary exposure, improve reliability and help prevent monitoring failures from going unnoticed.

---

## 🏗️ Architecture

Agent Security runs as a lightweight Python daemon.

```text
agent-security/
├── alertbot/
│   ├── approval/
│   │   ├── service.py
│   │   └── helper.py
│   ├── ssh.py
│   ├── journal.py
│   ├── filesystem.py
│   ├── fail2ban.py
│   ├── crowdsec.py
│   ├── dangerous_commands.py
│   └── telegram.py
├── deploy/
├── docs/
├── LICENSE
├── MANIFEST.in
├── pyproject.toml
└── README.md
```

The daemon shares a configuration object, Telegram sender and shutdown event across independently running monitoring threads.

This keeps event detection separate from notification delivery while allowing the service manager to recover from unexpected worker failures.

## 🚀 Getting Started

### Requirements

- Linux with `systemd`
- Python environment compatible with the project's `pyproject.toml`
- Telegram bot credentials and a destination for notifications
- Appropriate system permissions for the monitoring modules you enable

### Installation

Clone the repository:

```bash
git clone https://github.com/iAghaTraker/agent-security.git
cd agent-security
```

Inspect the installation and deployment instructions:

```bash
cat pyproject.toml
ls deploy/
ls docs/
```

Follow the repository's deployment instructions to configure the service, Telegram credentials and the monitoring modules required for your environment.

> ⚠️ Run with only the privileges required by the enabled monitors. Review deployment scripts and approval hooks before installing them on a production server.

## 🎯 Design Philosophy

| Principle | Commitment |
|---|---|
| Reliability | Monitoring failures should not go unnoticed. |
| Isolation | One component's failure should not silently disable the others. |
| Signal over noise | Alerts should be meaningful, deduplicated and controlled. |
| Fail-closed authorization | An unavailable approval mechanism must not grant access. |
| Accountability | Dangerous-command alerts should preserve reliable user attribution. |
| Simplicity | Keep monitoring focused and infrastructure lightweight. |

---

## 🤝 Contributing

Security improvements, bug reports and thoughtful contributions are welcome.

1. Open an issue describing the problem or proposed improvement.
2. Keep changes focused and reviewable.
3. Include tests or reproducible verification where appropriate.
4. Document security-sensitive behavior and configuration changes.

Please report security vulnerabilities responsibly rather than publishing exploitable details in a public issue.

---

## ⭐ Support the Project

If Agent Security is useful to your infrastructure, consider giving the repository a star.

It helps other developers discover the project and supports continued open-source development.

<p align="center">
  <strong>AGENT SECURITY</strong><br>
  <sub>Independent monitors. Centralized alerts. Fail-closed authorization.</sub><br><br>
  <a href="https://github.com/iAghaTraker/agent-security">Explore the Repository ↗</a>
</p>
