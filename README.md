# SentinelScan AI

> **Know who is probing your network before they get in.**

Real-time network reconnaissance detection and alert system. Captures live packets, classifies the scan technique, fingerprints the scanning tool, profiles the attacker, scores risk, and dispatches alerts — all behind a live Tailwind dashboard.

---

## How it works

### 1. Packet capture

SentinelScan listens on a network interface using **Scapy** (Windows via Npcap, Linux via libpcap). If no capture interface is available, a **Simulation mode** generates realistic multi-tool attack profiles (Nmap, Masscan, Angry IP Scanner, Zenmap) so you can test the full system without real traffic.

When the engine is running, every packet is summarized and fed into the detection engine.

### 2. Detection engine

The engine maintains a **sliding window per source IP** (default: 15 seconds). When a source crosses any threshold — too many unique ports, too many unique destinations, or too many packets per second — it triggers a full analysis:

| Threshold | Default | What it catches |
| --- | --- | --- |
| `PORT SWEEP` | 20 unique ports | Port scanning a single host |
| `HOST SWEEP` | 15 unique targets | Network sweep / reconnaissance |
| `RATE` | 200 pkts/sec | High-speed mass scan |

### 3. Classification & fingerprinting

Once a scan is detected, the system:

- **Classifies the scan type** — SYN Stealth, TCP Connect, FIN, Xmas, NULL, UDP, Ping Sweep, ACK, Fragmented, Mass Scan, Service Enumeration, and more
- **Fingerprints the tool** — identifies Nmap, Zenmap, Masscan, Angry IP Scanner, or Custom scanner with a confidence percentage (based on TCP window size, TTL, packet ordering, flag combinations)
- **Profiles the attacker** — resolves MAC address (on-link), reverse DNS hostname, estimates OS (Windows / Linux via TTL + window size), and looks up ASN/ISP/country
- **Maps to MITRE ATT&CK** — assigns a tactic and technique ID (T1046 Network Service Discovery, T1018 Remote System Discovery, etc.)
- **Scores risk** — 0–10 score with low / medium / high / critical levels, boosted by AbuseIPDB reputation when configured
- **Explains the attack** — generates a ranked list of likely reasons (legitimate cloud service, security scanner, actual attack, false positive) with supporting and contradicting evidence

### 4. Alerts

When a scan is detected, alerts can be dispatched through multiple channels:

- **Desktop notification** (via plyer) — instant popup on Windows/macOS/Linux
- **Email (SMTP)** — configurable server, TLS support, tested with Gmail App Passwords
- **Telegram bot** — real-time alerts with block/allow buttons, supports both long polling and webhook modes

Each alert has a cooldown per source IP (default: 120 seconds) to prevent flooding.

### 5. IPS — Intrusion Prevention System

The IPS module turns detection into action. It has three modes:

| Mode | Behaviour |
| --- | --- |
| `alert_only` | Log everything, never block |
| `approve` | Create a **pending action** when risk is moderate (`≥ 4.0`). The operator decides: **Allow** (adds to whitelist, stops alerts) or **Block** (locks the IP via firewall). High-risk scans (`≥ 8.0`) are auto-blocked immediately. |
| `auto_block` | Block every detected scanner above the threshold |

#### How blocking works (two layers)

```
                    ┌───────────────────────────────┐
                    │       OS Firewall Layer       │
                    │ (Windows Defender / iptables) │
                    │ Drops packets at kernel level │
                    │     nmap sees: "filtered"     │
                    │ Requires: Admin + FW running  │
                    └───────────────────────────────┘
                                    │
                    ┌───────────────────────────────┐
                    │       Application Layer       │
                    │  (Flask before_request hook)  │
                    │   Rejects HTTP at port 5000   │
                    │    nmap sees: "open" still    │
                    │    Works without Admin/FW     │
                    └───────────────────────────────┘
```

**Layer 1 — OS Firewall (Windows Defender / iptables / nftables)**

When you click **Block**, SentinelScan runs the OS firewall command:

- **Windows**: `New-NetFirewallRule -RemoteAddress <IP> -Action Block` — creates a kernel-level filter. The OS drops all packets from that IP before any application sees them. Nmap shows `filtered`.
- **Linux**: `iptables -A INPUT -s <IP> -j DROP` — same effect.

> **Requirements**: On Windows, SentinelScan must run **as Administrator** and the **Windows Firewall service (MpsSvc) must be running**. The dashboard shows a red banner if either condition is unmet.

If the direct PowerShell command fails (e.g. running as a service account), SentinelScan falls back to `schtasks` to execute the rule as the SYSTEM account.

**Layer 2 — Application middleware (Flask)**

A `before_request` hook on every HTTP request checks if the source IP is in the blocked list. If it is, Flask returns `403 Forbidden` before the request reaches any route.

This protects the SentinelScan dashboard (port 5000) even when the OS firewall can't be used — but it only blocks **HTTP requests**, not raw TCP connections. Nmap will still show the port as `open` (the TCP handshake completes), but any actual HTTP request from the blocked IP gets rejected.

**Verification & repair**

Every block attempt follows a strict **apply → verify** sequence:

1. `apply_block()` — creates the OS firewall rule
2. `verify_block()` — confirms the rule actually exists in the OS
3. Status is saved as `VERIFIED` (rule active) or `FAILED` (with full diagnostic: command, exit code, stderr)

On startup, all persisted blocks are re-checked. Missing rules are repaired automatically. Permanently broken rules are marked `FAILED` so the operator knows what's broken.

**Whitelist**

When you click **Allow** on a pending action, the source IP is added to an in-memory whitelist with a configurable TTL (default: 5 minutes). Whitelisted IPs stop triggering alerts and are never blocked. Expired entries are cleaned up automatically.

**Pending rate limiter**

While a decision is pending, the source IP is rate-limited (token bucket, 50 tokens/sec) to prevent a heavy scan from flooding the dashboard with pending actions.

### 6. ML Attack Prediction

When `scikit-learn` and `numpy` are installed, SentinelScan trains two models from historical attack data:

- **Escalation classifier** — predicts whether a source will escalate to more aggressive scans within 10 minutes
- **Port association model** — predicts the next ports the attacker is likely to target (based on co-occurrence patterns)

The models retrain every 30 seconds in the background and are used on the attack detail page.

### 7. Reports

- **PDF** (via ReportLab) — executive summary, threat statistics, source analysis, timeline chart, and tailored recommendations
- **CSV** — raw attack log for import into SIEMs or spreadsheets

Reports cover a configurable time window and can be emailed on a schedule (daily/weekly).

### 8. Encrypted storage

Sensitive log fields (source IPs, target ports, scan signals) can be encrypted at rest using **Fernet (AES-128-CBC + HMAC-SHA256)** with a key derived from `SENTINEL_SECRET_KEY` via PBKDF2-HMAC-SHA256 (200,000 iterations). Toggle with `SENTINEL_ENCRYPT_LOGS=true`.

### 9. Threat intelligence

When `SENTINEL_THREAT_INTEL_ENABLED=true` and an AbuseIPDB API key is configured, every detected source IP is checked against AbuseIPDB's reputation database. IPs with `abuseConfidenceScore ≥ 50` get a +1.0 risk boost.

---

## Quick start

```bash
# 1. Install dependencies
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1
# Linux:   source .venv/bin/activate
pip install -r requirements.txt

# 2. (Optional) configure alerts & IPS
copy .env.example .env   # Windows
# cp .env.example .env   # Linux
# Edit .env — at minimum set SENTINEL_IPS_ENABLED=true

# 3. Run
python run.py
```

Open **http://localhost:5000** in a browser. Click **Start** to bring the engine up.

### Running as Administrator (Windows — required for firewall blocking)

```
start.bat          # auto-elevates via UAC prompt
```

Or manually:
```
# Right-click PowerShell → Run as Administrator
python run.py
```

### Live capture (real packets)

- **Windows:** Install [Npcap](https://npcap.com) and run in an Administrator terminal. Choose **Live** mode.
- **Linux:** `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python))` (or run as root). Choose **Live**.

If you don't have those, **Simulation** mode ships with realistic attacker profiles and produces the same detections.

---

## Configuration

All settings live in environment variables (or a `.env` file). See [`.env.example`](./.env.example) for the complete list. Key settings:

### Detection

| Variable | Default | Description |
| --- | --- | --- |
| `SENTINEL_WINDOW_SECONDS` | `15` | Sliding window for rate analysis |
| `SENTINEL_PORTSWEEP_THRESHOLD` | `20` | Unique ports per source to flag |
| `SENTINEL_HOSTSWEEP_THRESHOLD` | `15` | Unique targets per source to flag |
| `SENTINEL_RATE_THRESHOLD` | `200` | Packets/sec per source to flag |
| `SENTINEL_ALERT_COOLDOWN` | `120` | Seconds between repeat alerts per source |

### IPS

| Variable | Default | Description |
| --- | --- | --- |
| `SENTINEL_IPS_ENABLED` | `false` | Enable the IPS module |
| `SENTINEL_IPS_MODE` | `approve` | `approve`, `auto_block`, or `alert_only` |
| `SENTINEL_IPS_APPROVAL_TIMEOUT` | `60` | Seconds before a pending action expires |
| `SENTINEL_IPS_AUTO_BLOCK_THRESHOLD` | `8.0` | Risk ≥ this triggers auto-block |
| `SENTINEL_IPS_APPROVAL_THRESHOLD` | `4.0` | Risk ≥ this requires operator approval |
| `SENTINEL_IPS_BLOCK_EXPIRY` | `0` | Seconds until auto-unblock (0 = never) |

### Telegram

1. Create a bot via [@BotFather](https://t.me/BotFather), copy the token
2. Send any message to the bot, then call `https://api.telegram.org/bot<TOKEN>/getUpdates` to get your chat ID
3. Set `SENTINEL_TELEGRAM_ENABLED=true`, `SENTINEL_TELEGRAM_BOT_TOKEN`, and `SENTINEL_TELEGRAM_CHAT_ID` in `.env`

### Lost admin password

- Set `SENTINEL_ADMIN_PASSWORD` in `.env` and restart — the password is reset on boot
- Or: `python -m backend.auth_cli reset <new-password>` (works against the same database without starting the server)

---

## API

### Engine & status

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/status` | Engine summary + settings + firewall stats |
| `GET` | `/api/stats` | Dashboard payload (timeline, risk, scans, tools, countries, top sources) |
| `POST` | `/api/engine/start` | Start engine `{ "mode": "auto" \| "live" \| "sim" }` |
| `POST` | `/api/engine/stop` | Stop the engine |

### Attacks

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/attacks?limit=100&offset=0` | Recent attacks |
| `GET` | `/api/attacks/<id>` | One attack with full profile + ML predictions |
| `GET` / `POST` | `/api/attacks/<id>/ack` | Acknowledge (GET via email token, POST via dashboard) |

### IPS & Firewall

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/ips/status` | IPS on/off, mode, thresholds, firewall health |
| `GET` | `/api/ips/pending` | Pending approval actions |
| `GET` | `/api/ips/blocked` | Blocked IPs with enforcement status |
| `POST` | `/api/ips/block` | Manually block an IP `{ "ip": "..." }` |
| `POST` | `/api/ips/unblock` | Manually unblock an IP `{ "ip": "..." }` |
| `POST` | `/api/ips/allow/<action_id>` | Approve a pending action (allow, add to whitelist) |
| `POST` | `/api/ips/block/<action_id>` | Deny a pending action (block IP) |
| `POST` | `/api/ips/deny/<action_id>` | Same as block (legacy alias) |
| `POST` | `/api/ips/whitelist/<ip>/block` | Remove from whitelist and block |
| `GET` | `/api/ips/whitelist` | List whitelisted entries |
| `DELETE` | `/api/ips/whitelist/<ip>` | Remove from whitelist (no block) |
| `POST` | `/api/ips/settings` | Update IPS settings `{ "enabled": true, "mode": "auto_block" }` |
| `GET` | `/api/firewall/rules` | All firewall rules with enforcement diagnostics |
| `POST` | `/api/firewall/unblock/<ip>` | Remove a firewall rule |
| `POST` | `/api/firewall/selftest` | Run end-to-end firewall test (create, verify, remove) |
| `POST` | `/api/firewall/rediagnose/<ip>` | Re-run apply_block to capture current diagnostics |

### Alerts & packets

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/alerts?limit=50` | Alert audit log |
| `GET` | `/api/packets?limit=40` | Live packet feed |

### Reports

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/reports/pdf` | Download PDF report |
| `GET` | `/api/reports/csv` | Download CSV log |
| `GET` | `/api/reports/schedules` | List report schedules |
| `POST` | `/api/reports/schedules` | Create a schedule |
| `POST` | `/api/reports/schedules/<id>/run` | Run a scheduled report immediately |

### Timeline

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/sources/<ip>/timeline?since=<ISO>` | Attack + packet timeline for a source |

### Auth

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/auth/me` | Current user info |
| `POST` | `/api/auth/login` | `{ "username": "...", "password": "..." }` |
| `POST` | `/api/auth/logout` | End session |
| `POST` | `/api/auth/change-password` | `{ "current_password": "...", "new_password": "..." }` |

---

## Dashboard

The frontend is a single-page application (Tailwind CSS + Chart.js) served by Flask at `/`. It shows:

- **Real-time attack timeline** — streamed via Server-Sent Events
- **Risk distribution** — doughnut chart (low/medium/high/critical)
- **Scan type distribution** — bar chart
- **Tool breakdown** — identified scanners
- **Country map** — source IP geolocation
- **Top attacker sources** — ranked by packet count
- **Live packet feed** — scrollable per-packet view
- **IPS controls** — enable/disable, mode selector, pending actions, whitelist management, blocked IPs with enforcement status banner
- **Alert channels** — live status of each configured alert channel

---

## Testing

```bash
pip install pytest
pytest tests/                  # all tests (351+)
pytest tests/ -v -k firewall   # firewall-specific tests
pytest tests/ -v -k ips        # IPS-specific tests
```

---

## Project layout

```
├── backend/
│   ├── alerts.py              # Alert dispatch (desktop, email, Telegram)
│   ├── app.py                 # Flask application + REST API routes
│   ├── approval_manager.py    # IPS pending actions (approve/deny/expire)
│   ├── arp.py                 # ARP cache reader for on-link MAC resolution
│   ├── audit.py               # IPS decision audit log
│   ├── auth.py                # Authentication (login, session, bootstrap)
│   ├── auth_cli.py            # CLI tool for password recovery
│   ├── capture.py             # Live (Scapy) + simulation packet capture
│   ├── classifier.py          # Scan type classification
│   ├── config.py              # Settings loader (.env → dataclass)
│   ├── crypto.py              # Fernet encryption for sensitive log fields
│   ├── database.py            # SQLAlchemy models + queries
│   ├── detector.py            # Sliding-window detection engine
│   ├── events.py              # SSE event broadcaster
│   ├── explanation.py         # Attack explanation engine
│   ├── fingerprinter.py       # Tool fingerprinting (Nmap, Masscan, etc.)
│   ├── firewall_manager.py    # OS firewall abstraction (Windows/Linux)
│   ├── ips_policy.py          # IPS policy thresholds
│   ├── mitre.py               # MITRE ATT&CK technique mapping
│   ├── oui.py                 # OUI MAC vendor lookup
│   ├── pending_rate_limiter.py# Token-bucket rate limiter for pending sources
│   ├── predictor.py           # ML attack prediction models
│   ├── profiler.py            # IP → profile (hostname, ASN, country, OS)
│   ├── reports.py             # PDF + CSV report generation
│   ├── risk.py                # Risk scoring engine
│   ├── rules.py               # MITRE ATT&CK rule definitions
│   ├── scheduler.py           # Scheduled report emailer
│   ├── telegram_ips.py        # Telegram bot with block/allow commands
│   ├── threat_intel.py        # AbuseIPDB reputation lookup
│   └── whitelist_manager.py   # Temporary whitelist with TTL + expiry
├── frontend/
│   ├── index.html             # Main dashboard SPA
│   ├── login.html             # Login page
│   └── static/
│       ├── css/style.css      # Tailwind styles
│       └── js/app.js          # Dashboard controller
├── tests/                     # Pytest test suite (351+ tests)
├── data/                      # SQLite database location
├── reports/                   # Generated PDF + CSV files
├── logs/                      # Application logs
├── .env.example               # All configurable env vars with docs
├── PRD.txt                    # Full product requirements document
├── requirements.txt           # Python dependencies
├── start.bat                  # Windows launcher with auto-elevation
└── run.py                     # Entry point
```

---

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| **Blocking doesn't work — nmap still shows "open"** | Windows Firewall must be ON and SentinelScan must run as Administrator. The dashboard shows a red banner when enforcement is unavailable. |
| **Live mode falls back to simulation** | Npcap missing (Windows) or no raw socket privileges (Linux). See quick start. |
| **`ModuleNotFoundError: scapy`** | `pip install scapy` (only needed for live mode) |
| **`ModuleNotFoundError: reportlab`** | `pip install reportlab` (only needed for PDF reports) |
| **Telegram/email alerts don't fire** | Verify credentials in `.env`. Each failed dispatch is recorded in `/api/alerts`. |
| **Browser stuck on stale state** | Click the ↻ refresh button in the dashboard header. |
| **Forgot admin password** | Set `SENTINEL_ADMIN_PASSWORD` in `.env` and restart, or use `python -m backend.auth_cli reset <password>`. |

---

## Security notes

- Run SentinelScan on a host you control. Live capture requires raw socket access.
- Override `SENTINEL_SECRET_KEY` before exposing the API publicly.
- Outbound alerts can leak attacker details — review your alert channels.
- The bundled IP → country/ASN table is illustrative. For production, swap `_demo_lookup()` in `profiler.py` for a MaxMind GeoLite2 or IPinfo call.
- Set `SENTINEL_PROXY_FIX_COUNT` when behind a reverse proxy so rate-limiting and logs use the real client IP.
