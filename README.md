<div align="center">

```
███████╗██╗   ██╗██╗   ██╗ █████╗ ██████╗  ██████╗ ███╗   ██╗
╚══███╔╝╚██╗ ██╔╝██║   ██║██╔══██╗██╔══██╗██╔═══██╗████╗  ██║
  ███╔╝  ╚████╔╝ ██║   ██║███████║██████╔╝██║   ██║██╔██╗ ██║
 ███╔╝    ╚██╔╝  ╚██╗ ██╔╝██╔══██║██╔══██╗██║   ██║██║╚██╗██║
███████╗   ██║    ╚████╔╝ ██║  ██║██║  ██║╚██████╔╝██║ ╚████║
╚══════╝   ╚═╝     ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
```

### Autonomous Cybersecurity Platform

**Detect. Block. Recover. Automatically.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6?style=flat-square&logo=windows)](https://microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)]()
[![Version](https://img.shields.io/badge/Agent-v0.3.0-brightgreen?style=flat-square)]()

</div>

---

## What is ZYVARON?

ZYVARON is a **self-hosted autonomous cybersecurity agent** that runs silently on your Windows machine and protects it in real time — without requiring any security knowledge to operate.

While you work, sleep, or do anything else, ZYVARON is:
- Scanning 10,000 network ports every hour and **permanently blocking dangerous ones**
- Taking a **snapshot of every file every 5 minutes** so deleted files can be recovered instantly
- Checking all installed software against the **NIST National Vulnerability Database** for known CVEs
- Displaying everything on a **live security dashboard** at `localhost:8000` Currently running on local machine it still in development.

> *"ZI-vah-ron — Defend Everything. Recover Anything."*

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running ZYVARON](#running-zyvaron)
- [Dashboard](#dashboard)
- [Remediation Modes](#remediation-modes)
- [CVE Scanner](#cve-scanner)
- [File Vault & Recovery](#file-vault--recovery)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Architecture Overview

ZYVARON is built as three decoupled layers that communicate over a local REST API:

```
┌─────────────────────────────────────────────────────────┐
│                    ZYVARON AGENT                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │  Port    │ │  File    │ │   CVE    │ │Remediat. │  │
│  │ Scanner  │ │  Vault   │ │ Checker  │ │  Engine  │  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘  │
│       └─────────────┴───────────┴─────────────┘        │
│                         │  REST API calls               │
└─────────────────────────┼───────────────────────────────┘
                          │
┌─────────────────────────┼───────────────────────────────┐
│              FASTAPI SERVER  :8000                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ /agents  │ │ /alerts  │ │  /files  │ │  /cve    │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
│                    SQLite Database                      │
└─────────────────────────┬───────────────────────────────┘
                          │
┌─────────────────────────┼───────────────────────────────┐
│               DASHBOARD  (index.html)                   │
│         Browser-based live security interface           │
└─────────────────────────────────────────────────────────┘
```

---

## Features

### 🔒 Automatic Port Blocker
Detects dangerous open network ports and creates permanent Windows Firewall rules in **under 4 seconds**. No user interaction required.

| Port | Service | Threat |
|------|---------|--------|
| 445  | SMB     | WannaCry / EternalBlue ransomware vector |
| 3389 | RDP     | Brute-force remote access attacks |
| 23   | Telnet  | Cleartext credential exposure |
| 21   | FTP     | Unencrypted file transfer |
| 1433 | MSSQL   | Database exploitation |
| 3306 | MySQL   | Database exploitation |
| 5900 | VNC     | Unauthorised remote desktop |

### 📁 File Vault & Recovery
Every monitored file is snapshotted every 5 minutes with SHA-256 hash verification. If a file is deleted — by ransomware, accident, or anything else — it can be restored to its exact original path in approximately 30 seconds.

- **Snapshot interval:** 5 minutes
- **Hash algorithm:** SHA-256
- **Recovery time:** ~30 seconds
- **Integrity check:** Every snapshot is verified on restore

### 🔍 CVE Vulnerability Scanner
Reads all installed applications from the Windows registry and checks them against the [NIST NVD API](https://nvd.nist.gov/). Results include:
- CVSS v3 severity score and rating (Critical / High / Medium)
- Affected software name and version
- Exact `winget` command to patch each vulnerability
- Rescans automatically every 6 hours

### ⚡ Remediation Engine
Three operational modes switchable live from the dashboard without restarting the agent:

| Mode   | Behaviour |
|--------|-----------|
| SMART  | Auto-blocks dangerous ports and detects CVEs. Files managed manually. *(Default)* |
| AUTO   | Fully autonomous. Recovers deleted files automatically, runs `winget` updates silently. |
| MANUAL | Detect and alert only. Zero automatic actions taken. Full user control. |

### 📊 Live Security Dashboard
A single-file browser dashboard at `localhost:8000` showing:
- Real-time system health (CPU, RAM, Disk)
- Active and resolved security alerts
- Complete file event log with recovery controls
- CVE scan results and patch status
- Port scan history
- Remediation mode switcher
- Connected device overview

### 🛡 Threat Detection & Alert Engine
Classifies and prioritises threats with smart cooldown timers to prevent alert fatigue:
- **CRITICAL** — dangerous port exposure, mass file deletion (>10 files), CVE score ≥ 9.0
- **HIGH** — suspicious port open, CVE score ≥ 7.0
- **MEDIUM** — elevated resource usage, CVE score ≥ 4.0
- Smart cooldowns: CPU 10 min, RAM 10 min, Disk 30 min

---

## Project Structure

```
ZYVARON/
│
├── Agent/
│   └── Agent/
│       ├── agent_core.py           # Main agent loop — entry point
│       └── modules/
│           ├── system_collector.py # CPU, RAM, disk, OS info
│           ├── port_scanner.py     # Network port detection
│           ├── file_vault.py       # File monitoring & snapshots
│           ├── reporter.py         # Sends data to server API
│           ├── cve_checker.py      # CVE vulnerability scanner
│           └── remediation_engine.py # Threat response logic
│
├── server/
│   ├── main.py                     # FastAPI app entry point
│   ├── db/
│   │   └── database.py             # SQLAlchemy models & DB setup
│   ├── api/
│   │   ├── agents.py               # Agent reporting endpoints
│   │   ├── alerts.py               # Alert management endpoints
│   │   ├── devices.py              # Device registry endpoints
│   │   ├── files.py                # File event & recovery endpoints
│   │   └── cve.py                  # CVE scan endpoints
│   └── services/
│       └── alert_engine.py         # Alert classification & cooldowns
│
├── Dashboard/
│   └── index.html                  # Single-file live dashboard
│
├── requirements.txt
└── README.md
```

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | Tested on 3.14.3 |
| Windows | 10 / 11 | Required for Firewall API & Registry access |
| Administrator privileges | — | Required for firewall rule creation |
| Internet connection | — | Required for CVE database sync |


## Running ZYVARON

ZYVARON requires **two terminal windows** — one for the server and one for the agent.

### Terminal 1 — Start the Server

```powershell
cd ZYVARON\server
.\.venv\Scripts\Activate.ps1
uvicorn main:app --host 0.0.0.0 --port 8000
```

Expected output:
```
ZYVARON Server starting...
Database ready [OK]
Server live at http://localhost:8000
API docs at   http://localhost:8000/docs
```

### Terminal 2 — Start the Agent

```powershell
cd ZYVARON\Agent\Agent
..\..\..\.venv\Scripts\Activate.ps1
python agent_core.py
```

Expected output:
```
[ZYVARON] Agent v0.3.0 starting...
[ZYVARON] System info collected
[ZYVARON] 11 files indexed | Snapshot created
[ZYVARON] Port scan: 10,000 ports...
[ZYVARON] ⚠ Port 445 (SMB) detected — creating firewall rule
[ZYVARON] ✓ Port 445 BLOCKED permanently
```

### Open the Dashboard

Open `Dashboard/index.html` in any browser. It connects to `localhost:8000` automatically.

---

## Dashboard

The dashboard is a single HTML file with no build step or dependencies. Open it directly in your browser:

```
Dashboard/index.html
```

**Pages available:**
- **Overview** — System health, active alerts, quick stats
- **Devices** — Registered agents and their status
- **Alerts** — Active and resolved security alerts with remediation controls
- **File Vault** — Monitored files, deleted file log, recovery button
- **Port Scanner** — Port scan history, blocked ports, firewall rules
- **CVE Scanner** — Vulnerability scan results, CVSS scores, patch commands
- **Remediation** — Mode switcher (Smart / Auto / Manual)

---

## Remediation Modes

Switch modes anytime from the dashboard Remediation page. The agent polls for mode changes every **30 seconds** — no restart required.

```
Smart Mode  (Default)
├── ✓ Blocks dangerous ports automatically
├── ✓ Detects CVE vulnerabilities
├── ✓ Alerts on file deletions
└── ✗ Does NOT auto-recover files

Auto Mode
├── ✓ Everything in Smart mode
├── ✓ Auto-recovers deleted files from vault
├── ✓ Runs winget software updates silently
└── ✓ Fully hands-free — zero user interaction needed

Manual Mode
├── ✓ Detects all threats and logs them
├── ✗ Takes NO automatic actions
└── ✓ Full audit trail — you approve every action
```

---

## CVE Scanner

The CVE scanner reads installed applications from the Windows registry using PowerShell and queries the [NIST NVD REST API v2](https://nvd.nist.gov/developers/vulnerabilities).

**How it works:**
1. Reads installed software from `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
2. Maps software names to NVD search keywords via `SOFTWARE_CPE_MAP`
3. Fetches CVEs with CVSS ≥ 4.0 from the NVD API
4. Generates a `winget upgrade` command for each patchable vulnerability
5. Results cached for 6 hours in `cve_cache.json`
6. Rescans automatically every 6 hours

**CVE results are stored separately from security alerts.** They appear only in the CVE section of the dashboard and do not affect the security overview status.

**Example output:**
```
CVE-2015-7082  Git 2.53.0   CRITICAL  10.0  → winget upgrade Git.Git
CVE-2026-3916  Chrome 146   CRITICAL   9.6  → winget upgrade Google.Chrome
CVE-2026-3913  Chrome 146   HIGH       8.8  → winget upgrade Google.Chrome
```

---

## File Vault & Recovery

### How snapshots work

On startup, ZYVARON indexes all files in the monitored directory and takes an initial snapshot. Every 5 minutes, it takes a new snapshot of all monitored files.

```
Startup     → snap_startup
+5 min      → snap_1
+10 min     → snap_2
...
File deleted → detected within 60 seconds
Recovery    → searches newest snapshot backwards
             → copies file to original path
             → verifies SHA-256 hash
```

### Requesting a recovery

From the dashboard **File Vault** page:
1. Find the deleted file in the deleted files list
2. Click **RECOVER**
3. The agent receives the request within 30 seconds
4. File is restored to its exact original path
5. Dashboard confirms with hash verification status

### What ZYVARON monitors

By default, ZYVARON monitors the user's `Documents` folder and excludes its own internal files to prevent self-monitoring loops.

**Excluded directories:** `ZYVARON/`, `.venv/`, `__pycache__/`  
**Excluded files:** `zyvaron.db`, `*.log`, `cve_cache.json`

---

## API Reference

The server exposes a full REST API. Interactive docs available at `http://localhost:8000/docs` when the server is running.

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/agent/report` | Agent submits system report |
| `GET`  | `/api/devices/` | List all registered devices |
| `GET`  | `/api/devices/{id}/summary` | Device summary with latest stats |

### Alerts

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/alerts/` | Get active alerts (excludes CVEs) |
| `GET`  | `/api/alerts/all` | Get all alerts with resolved history |
| `GET`  | `/api/alerts/stats` | Alert count summary |
| `POST` | `/api/alerts/resolve-by-type` | Resolve all alerts of a given type |
| `PUT`  | `/api/alerts/{id}/resolve` | Resolve a specific alert |
| `GET`  | `/api/alerts/remediation-mode` | Get current remediation mode |
| `POST` | `/api/alerts/remediation-mode` | Set remediation mode |

### File Vault

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/files/stats` | File monitoring statistics |
| `GET`  | `/api/files/deleted` | List deleted files |
| `GET`  | `/api/files/events` | Full file event log |
| `POST` | `/api/files/request-recovery` | Request file recovery |

### CVE Scanner

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/cve/scan` | Submit CVE scan results from agent |
| `GET`  | `/api/cve/latest` | Latest scan for a device |
| `GET`  | `/api/cve/entries` | All CVE entries |
| `GET`  | `/api/cve/summary` | CVE counts by severity |
| `POST` | `/api/cve/resolve/{cve_id}` | Mark a CVE as patched |

---

## Configuration

Key settings are defined at the top of `agent_core.py`:

```python
# ── Scan intervals (seconds) ──────────────────────────────────────
FILE_SCAN_INTERVAL   = 60        # File integrity check frequency
SNAPSHOT_INTERVAL    = 300       # File snapshot frequency (5 minutes)
CVE_SCAN_INTERVAL    = 21600     # CVE rescan frequency (6 hours)
CVE_SCAN_DELAY       = 60        # Delay before first CVE scan on startup
MODE_SYNC_INTERVAL   = 30        # How often agent polls server for mode change

# ── Server connection ─────────────────────────────────────────────
SERVER_URL           = "http://localhost:8000"

# ── Blocked ports ─────────────────────────────────────────────────
ZYVARON_BLOCKED_PORTS = {3389, 445, 23, 21, 1433, 3306, 5900}
```

### Adding more ports to block

Edit `ZYVARON_BLOCKED_PORTS` in `agent_core.py`:

```python
ZYVARON_BLOCKED_PORTS = {3389, 445, 23, 21, 1433, 3306, 5900, 8080}
```

### Adding software to CVE scanning

Edit `SOFTWARE_CPE_MAP` in `modules/cve_checker.py`:

```python
SOFTWARE_CPE_MAP = {
    "google chrome":  "chrome",
    "git":            "git",
    "python":         "python",
    "your_software":  "nvd_search_keyword",  # add yours here
}
```

---

## Database

ZYVARON uses SQLite via SQLAlchemy. The database file `zyvaron.db` is created automatically in the `server/` directory on first run.

**Tables:**

| Table | Description |
|-------|-------------|
| `devices` | Registered agent devices |
| `system_reports` | CPU, RAM, disk reports from agents |
| `port_scan_reports` | Port scan history |
| `alerts` | Security alerts (excludes CVE type) |
| `file_events` | File create, modify, delete, recovery events |
| `snapshot_records` | File snapshot metadata |
| `cve_scans` | CVE scan session summaries |
| `cve_entries` | Individual CVE records per device |

To reset the database:
```powershell
del server\zyvaron.db
# Restart the server — tables recreate automatically
```

---

## Roadmap

- [x] Layer 1 — Autonomous Agent Core
- [x] Layer 2 — FastAPI REST Server
- [x] Layer 3 — Live Security Dashboard
- [x] Layer 4 — Remediation Engine (Smart / Auto / Manual)
- [x] Layer 5 — File Vault & Recovery
- [x] Layer 6 — CVE Vulnerability Scanner
- [ ] Layer 7 — AI Threat Detection Engine
- [ ] macOS agent support
- [ ] Linux agent support
- [ ] Multi-device enterprise dashboard
- [ ] Automated penetration testing module
- [ ] PDF security report generation
- [ ] Mobile dashboard (iOS / Android)

---

## Known Issues & Limitations

- **Windows only** — Firewall rule creation and registry access use Windows APIs. macOS/Linux support is on the roadmap.
- **Administrator required** — The agent must run as administrator to create Windows Firewall rules.
- **CVE scanning requires internet** — The NIST NVD API is queried externally. Offline mode is not currently supported.
- **Python 3.14 GIL warning** — A `RuntimeWarning` about the GIL appears when loading SQLAlchemy's C extensions. This is a Python 3.14 compatibility notice and does not affect functionality.

---

## Contributing

Contributions are welcome. Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes with clear commit messages
4. Ensure the server starts cleanly with `uvicorn main:app --host 0.0.0.0 --port 8000`
5. Ensure the agent starts cleanly with `python agent_core.py`
6. Open a pull request with a description of what changed and why

### Coding Standards

- Python files follow PEP 8
- All new API endpoints must have a corresponding entry in the API Reference section
- New database models must be added to `db/database.py` and listed in the Database section above
- No sensitive credentials or API keys in commits

---

## Security Notice

ZYVARON is a **local security tool** designed for personal and small business use. All data stays on your machine — nothing is sent to external servers except CVE lookups to the public NIST NVD API.

**Do not expose port 8000 to the public internet.** The dashboard and API have no authentication by default. If you need remote access, use a VPN or SSH tunnel.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**ZYVARON**

*Defend Everything. Recover Anything.*
