# Cyber Home Shield (v1.0.0)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI: 0.110+](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React: 18](https://img.shields.io/badge/React-18.3-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript: 5.5](https://img.shields.io/badge/TypeScript-5.5-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tailwind CSS: 3.4](https://img.shields.io/badge/Tailwind_CSS-3.4-38B2AC.svg?logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![AI: Meta Llama 3.2 / NVIDIA Nemotron](https://img.shields.io/badge/AI_Engine-Meta_Llama_3.2_/_NVIDIA_Nemotron-76B900.svg?logo=nvidia&logoColor=white)](https://build.nvidia.com/)
[![Database: PostgreSQL / Supabase](https://img.shields.io/badge/Database-PostgreSQL_/_Supabase-336791.svg?logo=postgresql&logoColor=white)](https://supabase.com/)
[![Tests: 143+ Passed](https://img.shields.io/badge/Tests-143+_Passed-brightgreen.svg?logo=pytest&logoColor=white)](https://docs.pytest.org/)

> **Next-Generation Defensive Home-Network Cybersecurity Platform**  
> Real-time RFC 1918 device discovery, deterministic mathematical risk scoring, multi-protocol stealth honeypot deception, Windows Netsh PortProxy integration, and low-latency NVIDIA/Meta AI threat advisory.

---

## Table of Contents

1. [Project Overview & Defensive Philosophy](#1-project-overview--defensive-philosophy)
2. [Key Capabilities & Innovations](#2-key-capabilities--innovations)
3. [System Architecture](#3-system-architecture)
4. [Technology Stack](#4-technology-stack)
5. [Subsystem Deep Dives](#5-subsystem-deep-dives)
   - [A. Dual-Phase Discovery Engine](#a-dual-phase-discovery-engine)
   - [B. Deterministic Risk & Posture Engine](#b-deterministic-risk--posture-engine)
   - [C. Multi-Protocol Stealth Honeypot Subsystem](#c-multi-protocol-stealth-honeypot-subsystem)
   - [D. Windows Netsh PortProxy Integration](#d-windows-netsh-portproxy-integration)
   - [E. CipherX AI Security Advisor (Llama 3.2 / Nemotron)](#e-cipherx-ai-security-advisor-llama-32--nemotron)
6. [Local Installation & Setup Guide](#6-local-installation--setup-guide)
7. [Configuration Reference (`.env`)](#7-configuration-reference-env)
8. [Windows PortProxy Setup Guide](#8-windows-portproxy-setup-guide)
9. [Testing & Quality Verification](#9-testing--quality-verification)
10. [Complete API Endpoint Reference](#10-complete-api-endpoint-reference)
11. [Academic Presentation & Report Artifacts](#11-academic-presentation--report-artifacts)
12. [Security Boundaries & Responsible Use](#12-security-boundaries--responsible-use)
13. [License & Acknowledgments](#13-license--acknowledgments)

---

## 1. Project Overview & Defensive Philosophy

Modern residential and small-office networks have become densely populated ecosystems of smart TVs, IP cameras, voice assistants, mobile devices, gaming consoles, and IoT sensors. While these devices provide unprecedented convenience, they introduce critical security vulnerabilities:
- Hardcoded or default administrative credentials.
- Unpatched embedded firmware with unencrypted communications (HTTP, Telnet, RTSP).
- Complete lack of local network visibility for non-technical homeowners.
- Inability of traditional firewalls to detect lateral movement or internal reconnaissance.

**Cyber Home Shield** bridges this gap. It is an ethical, defensive-only security operations platform engineered specifically for local networks. It provides non-technical homeowners and network administrators with:
1. **Total LAN Visibility**: Automated discovery of every authorized device with IEEE MAC vendor resolution and port profiling.
2. **Mathematically Provable Posture**: Continuous $0-100$ risk calculation based on open exposure, documented vulnerabilities, and telemetry anomalies.
3. **Active Early-Warning Deception**: Stealth honeypot traps that mimic vulnerable IoT devices to intercept internal network probes before real hardware is compromised.
4. **Context-Aware AI Guidance**: Instant, conversational remediation playbooks powered by state-of-the-art **Meta Llama 3.2 11B** and **NVIDIA Nemotron** models.

### Core Defensive Principles

```
  ┌────────────────────────────────────────────────────────────────────────┐
  │                        DEFENSIVE CORE TENETS                           │
  ├────────────────────────────────────────────────────────────────────────┤
  │ 1. Strict RFC 1918 Scope Confinement (No WAN Scans)                   │
  │ 2. Non-Destructive, Zero-Impact Discovery Probes                       │
  │ 3. Deterministic Risk Math (Zero AI Hallucination in Scoring)          │
  │ 4. Isolated, Command-Free Honeypot Deception Sandbox                  │
  │ 5. Strict Auto-Redaction of Intercepted Credentials                    │
  │ 6. Server-Side AI Privacy (Zero Client Secret Exposure)                │
  └────────────────────────────────────────────────────────────────────────┘
```

- **RFC 1918 Subnet Confinement**: Scanning, probing, and device mapping are strictly restricted to private address spaces (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and loopback `127.0.0.0/8`). Public WAN IPs, multicast, and broadcast ranges are categorically rejected at the Pydantic schema validation layer.
- **Deterministic Risk Scoring**: Risk values ($0–100$) are computed mathematically with sublinear dampening and clear evidence trails, ensuring repeatable posture assessments without relying on unpredictable LLM outputs.
- **Isolated Honeypot Deception**: Decoy traps execute zero system commands, proxy no traffic, auto-redact intercepted credentials (`[REDACTED]`), and can be bound safely to loopback (`127.0.0.1`) or local LAN (`0.0.0.0`).
- **Server-Side AI Privacy**: The NVIDIA NIM API key, prompts, and system instructions remain strictly server-side. No API keys or raw inference tokens are exposed to client browsers.

---

## 2. Key Capabilities & Innovations

- 🔍 **Dual-Phase Non-Destructive Discovery**: Instant harvest of OS ARP cache tables combined with bounded asynchronous ICMP ping sweeps and TCP port profiling, eliminating ghost devices while capturing silent endpoints.
- 🛡️ **Stealth IoT Honeypot Traps**: Emulates realistic IoT firmware banners (`mini_httpd/1.30`, `Dropbear SSH 2020.81`, `Boa/0.94.14rc21 RTSP`) with authentic HTTP 401 Basic authentication challenges and handshake capture.
- 🔀 **Windows Netsh PortProxy Integration**: Enables non-privileged user-space traps to intercept standard privileged ports (Port 80 $\to$ 8088, Port 22 $\to$ 2222, Port 554 $\to$ 8554) without running daemons as Administrator.
- 🧠 **CipherX AI Security Advisor**: Powered by **Meta Llama 3.2 11B Vision Instruct** / **NVIDIA Nemotron** via the NVIDIA NIM API. Features sub-8-second responses, 10-minute in-memory TTL caching to prevent rate-limit exhaustion, and offline deterministic fallback.
- 📊 **Interactive Cybersecurity Command Center**: Glassmorphic dark-mode UI with live posture gauges, device inventory, interactive honeypot management hub, probe simulator, and instant remediation playbooks.
- 🔒 **Multi-Tenant Security Architecture**: Password hashing via Argon2id, stateless JWT bearer authorization (HS256), sliding-window rate limiting, and strict tenant-scoped data isolation (IDOR protected).

---

## 3. System Architecture

```text
                                  CYBER HOME SHIELD
                                          │
                  ┌───────────────────────┴───────────────────────┐
                  │                                               │
             Real Devices                                  Honeypot Subsystem
       (Phones, PCs, Cameras, IoT)                          (Stealth Decoys)
                  │                                               │
                  │                                         Fake Services
                  │                                         ├── HTTP Web GUI (8088 / 80)
                  │                                         ├── Dropbear SSH (2222 / 22)
                  │                                         └── Boa Camera RTSP (8554 / 554)
                  │                                               │
                  └───────────────────────┬───────────────────────┘
                                          │
                                          ▼
                                   Event Collector
                                          │
                                          ▼
                             Telemetry & Anomaly Engine
                                          │
                                          ▼
                               Deterministic Risk Engine
                                          │
                                          ▼
                        NVIDIA NIM API (Llama 3.2 / Nemotron)
                                          │
                                          ▼
                           CipherX AI Security Advisor (UI)
```

### Full-Stack Architecture Layout

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                         React 18 Single-Page Application                         │
│   Posture Dashboard | Device Inventory | Discovery Scanner | Findings | Traps   │
│   CipherX AI Assistant | Netsh PortProxy Modal | Real-Time Probe Telemetry Logs  │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │ HTTP / JSON (JWT Bearer Auth)
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             FastAPI Backend Engine                               │
│   ├── Auth & Session Security (Argon2id + PyJWT + IDOR Tenant Isolation)         │
│   ├── RFC 1918 Scope Guard & Sliding-Window In-Memory Rate Limiter               │
│   ├── Dual-Phase Discovery Engine (OS ARP Cache Harvest + Async ICMP Sweeps)     │
│   ├── IEEE OUI MAC Vendor Resolution & Port Profiler (22, 53, 80, 443, 554, etc.)│
│   ├── Deterministic Risk Engine (Exposure + Vulnerabilities + Anomalies)         │
│   ├── Telemetry Baseline Tracker & Statistical Anomaly Engine                    │
│   ├── Isolated Honeypot Manager (LAN 0.0.0.0 / Loopback 127.0.0.1 Listeners)     │
│   ├── Stealth Traps (mini_httpd 8088, Dropbear SSH 2222, Boa RTSP Camera 8554)  │
│   ├── Probe Simulator & Automated Credential Redaction Sanitizer                 │
│   └── CipherX AI Client (Llama 3.2-11B / Nemotron + 10-Min In-Memory TTL Cache)   │
└────────────────────────────┬─────────────────────────────┬───────────────────────┘
                             │                             │
                             ▼                             ▼
              ┌─────────────────────────────┐   ┌─────────────────────────────┐
              │   PostgreSQL / Supabase     │   │     NVIDIA NIM Cloud API    │
              │ (AsyncPG + SQLAlchemy 2.0)  │   │  (meta/llama-3.2-11b /      │
              │   Alembic DB Migrations     │   │   nvidia/nemotron-4-340b)   │
              └─────────────────────────────┘   └─────────────────────────────┘
```

---

## 4. Technology Stack

| Domain | Technology / Library | Version | Role / Justification |
| :--- | :--- | :--- | :--- |
| **Backend Core** | Python | 3.11+ | High-performance asynchronous runtime |
| **API Framework** | FastAPI | >= 0.110.0 | High-speed async REST endpoints & auto OpenAPI docs |
| **ASGI Server** | Uvicorn | >= 0.28.0 | High-concurrency ASGI web server |
| **Data Validation** | Pydantic & Pydantic Settings | >= 2.6.0 | Strict type validation, RFC 1918 IP constraints |
| **Database ORM** | SQLAlchemy | >= 2.0.28 | Async 2.0 ORM with connection pooling |
| **Database Driver** | AsyncPG / aiosqlite | >= 0.29.0 | Non-blocking async driver for PostgreSQL & SQLite |
| **Migrations** | Alembic | >= 1.13.1 | Automated database schema evolution |
| **Password Hashing** | Passlib & Bcrypt (Argon2id) | >= 1.7.4 | Cryptographically hardened password storage |
| **Authentication** | PyJWT | >= 2.8.0 | Stateless JSON Web Token authentication (HS256) |
| **HTTP Client** | HTTPX | >= 0.27.0 | Non-blocking async client for NVIDIA NIM API calls |
| **Networking** | Scapy & Python-Nmap | >= 2.5.0 | Defensive ARP discovery & socket reachability |
| **Vendor Lookup** | mac-vendor-lookup | 0.1.15 | Resolves MAC OUI prefixes to hardware manufacturers |
| **AI Threat Advisory** | Meta Llama 3.2 11B / Nemotron | v1 | Fast (<8s) structured threat triage & hardening playbooks |
| **Frontend Core** | React 18 & TypeScript | 18.3 / 5.5 | Type-safe declarative single-page application |
| **Build Tool** | Vite | >= 5.4.0 | Ultra-fast HMR and optimized production bundling |
| **Styling** | Tailwind CSS | >= 3.4.0 | Modern responsive dark-mode cybernetic design system |
| **Icons & Visuals** | Lucide React & Recharts | Latest | Polished dashboard icons and responsive charts |
| **Testing** | Pytest & Pytest-Asyncio | >= 8.1.0 | 143+ comprehensive unit and integration tests |

---

## 5. Subsystem Deep Dives

### A. Dual-Phase Discovery Engine

The discovery engine profiles local network devices safely without saturating router bandwidth or triggering denial-of-service conditions:

1. **Phase 1 — Instant OS ARP Cache Extraction**:
   - Queries the operating system's kernel ARP cache table (`arp -a`).
   - Discovers all devices that have communicated with the host within milliseconds with zero packet transmission.
2. **Phase 2 — Bounded Asynchronous ICMP Echo Sweep**:
   - For unmapped IP addresses within the user's authorized CIDR (e.g. `192.168.1.0/24`), sends bounded, low-overhead ICMP echo requests (0.5s timeout).
   - Asynchronous concurrency is limited (`MAX_CONCURRENT_CHECKS=50`) to avoid network congestion.
3. **MAC Vendor Resolution & Filtering**:
   - Normalizes hardware addresses to `XX:XX:XX:XX:XX:XX` format and performs OUI manufacturer lookup (e.g. Apple, Raspberry Pi, Espressif, Samsung, Intel).
   - **Ghost Device Elimination**: Automatically filters out IPv4 broadcast addresses (`.255`), multicast ranges (`224.0.0.0/4`), and stale unconfirmed cache entries.
4. **Non-Intrusive Port Profiling**:
   - Evaluates standard defensive ports (`22, 53, 80, 443, 445, 554, 631, 8080, 8443`) using non-intrusive half-second connection probes.

### B. Deterministic Risk & Posture Engine

To eliminate unpredictable AI hallucinations from core security metrics, Cyber Home Shield computes posture scores using deterministic mathematical formulas:

$$\text{Total Score} = \min\Big(100, \; \text{Exposure Subscore} + \text{Vulnerability Subscore} + \text{Anomaly Subscore}\Big)$$

1. **Exposure Subscore**:
   - Computes risk based on exposed attack surface and cleartext protocols.
   - Telnet (`23`) = +20, SMB (`445`) = +15, HTTP (`80`) = +5, RTSP (`554`) = +8.
2. **Vulnerability Subscore**:
   - Aggregates security findings weighted by CVSS-aligned severity:
     - `CRITICAL`: 30 pts
     - `HIGH`: 15 pts
     - `MEDIUM`: 6 pts
     - `LOW`: 2 pts
     - `INFO`: 0 pts
   - Uses sublinear scaling ($\text{Score} = \text{Base} \times \sqrt{N}$) to prevent score runaway on multi-finding endpoints.
3. **Anomaly Subscore**:
   - Quantifies statistical deviations from 24-hour established traffic baselines (port scanning patterns, abnormal traffic surges, honeypot hits).
4. **Defensive Posture Tiers**:
   - 🟢 **Optimal ($0–25$)**: Minimal attack surface, zero high-severity vulnerabilities.
   - 🟡 **Moderate ($26–50$)**: Non-critical services exposed, firmware updates recommended.
   - 🟠 **Elevated ($51–75$)**: Unencrypted protocols detected, actionable hardening required.
   - 🔴 **Critical ($76–100$)**: Active security findings, unauthorized ports open, honeypot probes detected.

### C. Multi-Protocol Stealth Honeypot Subsystem

The honeypot subsystem operates as an internal early-warning tripwire. If an intruder or malware gains access to the Wi-Fi or LAN and begins port-scanning or probing, the decoy traps catch them immediately:

```text
      ┌────────────────────────────────────────────────────────┐
      │               REALISTIC STEALTH PROFILES               │
      ├────────────────────────────────────────────────────────┤
      │ 1. HTTP Router Gateway (Port 8088 / 80)                │
      │    - Server: mini_httpd/1.30 01Jan2018                 │
      │    - Authentic Router Web GUI with 401 Basic Auth      │
      │ 2. Dropbear Embedded SSH (Port 2222 / 22)              │
      │    - Banner: SSH-2.0-dropbear_2020.81\r\n              │
      │    - Protocol Handshake Capture                        │
      │ 3. Boa IP Camera RTSP (Port 8554 / 554)                │
      │    - Server: Boa/0.94.14rc21                           │
      │    - RTSP/1.0 401 Unauthorized RTSP/Basic Challenge    │
      └────────────────────────────────────────────────────────┘
```

- **Dual-Mode Binding**:
  - **Loopback Sandbox (`127.0.0.1`)**: Default safe mode for local machine testing.
  - **LAN Listener (`0.0.0.0`)**: Real network mode. Listens across all network adapters. Automatically resolves the machine's local LAN IP (e.g. `192.168.1.15`) for attacker reachability.
- **Safe Sandboxing & Credential Redaction**:
  - The traps do not execute shell commands or spawn subshells.
  - All intercepted HTTP authorization headers, SSH passwords, and request bodies are automatically scrubbed and stored as `[REDACTED]` to preserve privacy.
- **Probe Simulator**:
  - Allows one-click simulation of HTTP, SSH, and RTSP probes from the UI to test alerting and AI triage workflows safely.

### D. Windows Netsh PortProxy Integration

On Windows, non-administrator processes cannot bind to privileged ports ($< 1024$), such as Port 80 (HTTP) or Port 22 (SSH). Attackers scanning a network target standard ports (80, 22, 554), not high ports (8088, 2222, 8554).

Cyber Home Shield includes built-in **Netsh PortProxy integration**:
- The backend honeypots run safely as non-root user services on high ports (`8088`, `2222`, `8554`).
- Windows Native PortProxy forwards traffic arriving on privileged LAN ports directly to the honeypot traps.
- The UI includes an interactive **Port Proxy Helper Modal** that dynamically inspects the machine's LAN IP and generates one-click copyable PowerShell commands.

### E. CipherX AI Security Advisor (Llama 3.2 / Nemotron)

Cyber Home Shield integrates cutting-edge language models through the NVIDIA NIM API (`https://integrate.api.nvidia.com/v1`):

- **Active Model**: `meta/llama-3.2-11b-vision-instruct` (Ultra-fast, sub-8-second response latency).
- **Secondary Model**: `nvidia/nemotron-4-340b-instruct` (Deep architectural analysis).
- **Capabilities**:
  - **Interactive Security Chat**: Context-aware cyber assistant answering questions on network posture, open ports, and device vulnerabilities.
  - **Automated Incident Triage**: Explains intercepted honeypot events, identifying attacker intent (e.g., Mirai botnet reconnaissance, brute-force dictionary attacks).
  - **Tailored Hardening Playbooks**: Generates step-by-step instructions for specific router brands (Netgear, TP-Link, Asus) and IoT devices.
- **High-Performance Architecture**:
  - **In-Memory TTL Caching**: Honeypot event explanations are cached for 10 minutes (`_HONEYPOT_EXPLAIN_CACHE`). Repeated scans do not exhaust API rate limits or introduce UI latency.
  - **Resilient Fallback**: If the NVIDIA API key is omitted, times out, or experiences upstream outages, the advisor gracefully falls back to deterministic, rule-based security advice.

---

## 6. Local Installation & Setup Guide

### Prerequisites
- **Python**: Version 3.11 or higher
- **Node.js**: Version 18.0 or higher (with npm)
- **Database**: PostgreSQL 14+ (or SQLite for automated testing)
- **Optional**: Npcap (Windows) or Libpcap (Linux) for Layer-2 active ARP discovery

---

### Step 1: Clone the Repository
```bash
git clone https://github.com/your-username/cyber-home-shield.git
cd cyber-home-shield
```

---

### Step 2: Backend Setup

1. **Create and activate a Python virtual environment**:
   ```bash
   # Windows (PowerShell)
   python -m venv backend/.venv
   backend\.venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv backend/.venv
   source backend/.venv/bin/activate
   ```

2. **Install Python dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -r backend/requirements.txt
   ```

3. **Configure the Environment File**:
   Create or verify `backend/.env` (see the [Configuration Reference](#7-configuration-reference-env) section below):
   ```env
   APP_NAME="Cyber Home Shield"
   APP_VERSION="1.0.0"
   ENVIRONMENT="development"
   DEBUG=true

   DATABASE_URL="postgresql+asyncpg://postgres:postgres@localhost:5432/cyber_home_shield"
   SECRET_KEY="your-secure-random-32-character-secret-key-here"
   NVIDIA_API_KEY="nvapi-your-nvidia-api-key-here"
   NVIDIA_MODEL="meta/llama-3.2-11b-vision-instruct"
   NVIDIA_TIMEOUT=45.0

   HONEYPOT_ENABLED=true
   HONEYPOT_BIND_HOST="0.0.0.0"
   HONEYPOT_ALLOW_NON_LOCAL=true
   ```

4. **Run Database Migrations**:
   ```bash
   cd backend
   alembic upgrade head
   cd ..
   ```

5. **Start the FastAPI Backend Server**:
   ```bash
   # From the project root or backend directory:
   python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
   ```
   The backend API will be live at `http://localhost:8000` with interactive Swagger docs at `http://localhost:8000/docs`.

---

### Step 3: Frontend Setup

1. **Install Node.js dependencies**:
   ```bash
   npm install
   ```

2. **Start the Vite Frontend Development Server**:
   ```bash
   npm run dev
   ```
   The user interface will be live at `http://localhost:3000`.

---

## 7. Configuration Reference (`.env`)

The backend configuration is managed through Pydantic Settings in `backend/app/config.py`. All variables can be configured via `backend/.env`:

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `APP_NAME` | `"Cyber Home Shield"` | Display name of the application |
| `APP_VERSION` | `"1.0.0"` | Current platform semantic version |
| `ENVIRONMENT` | `"development"` | Environment (`development` or `production`) |
| `DEBUG` | `false` | Enables detailed logging and debug endpoints |
| `DATABASE_URL` | `postgresql+asyncpg://...` | Asynchronous SQLAlchemy database connection string |
| `SECRET_KEY` | *(Random 64+ char key)* | Secret key used for signing JWT tokens |
| `JWT_ALGORITHM` | `"HS256"` | JWT token encryption algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `1440` (24 Hours) | JWT token lifespan before re-login is required |
| `CORS_ORIGINS` | `http://localhost:3000,...` | Authorized frontend origins (comma-separated) |
| `NVIDIA_API_KEY` | `""` | NVIDIA NIM API key for CipherX AI advisor |
| `NVIDIA_MODEL` | `"meta/llama-3.2-11b-vision-instruct"`| Active LLM model (`meta/llama-3.2-11b-vision-instruct` recommended) |
| `NVIDIA_BASE_URL` | `"https://integrate.api.nvidia.com/v1"`| Base endpoint for NVIDIA NIM chat completions |
| `NVIDIA_TIMEOUT` | `45.0` | Maximum timeout in seconds for AI completions |
| `DISCOVERY_PROVIDER` | `"network"` | Discovery mode (`network` for real LAN, `mock` for testing) |
| `DISCOVERY_TIMEOUT` | `45.0` | Global timeout in seconds for a full discovery scan |
| `CONNECT_TIMEOUT` | `0.5` | Timeout per individual TCP socket port probe |
| `ICMP_PROBE_TIMEOUT` | `0.5` | Timeout per individual ICMP host echo probe |
| `MAX_HOSTS` | `254` | Maximum IP addresses scanned in a single subnet job |
| `MAX_CONCURRENT_CHECKS` | `50` | Maximum parallel asynchronous scan workers |
| `HONEYPOT_ENABLED` | `true` | Enables the deception trap subsystem |
| `HONEYPOT_BIND_HOST` | `"0.0.0.0"` | Network interface (`0.0.0.0` for LAN, `127.0.0.1` for loopback) |
| `HONEYPOT_ALLOW_NON_LOCAL` | `true` | Allows binding to non-loopback addresses |
| `HONEYPOT_HTTP_PORT` | `8088` | Listening port for the decoy HTTP router trap |
| `HONEYPOT_SSH_PORT` | `2222` | Listening port for the decoy Dropbear SSH trap |
| `HONEYPOT_CAMERA_PORT` | `8554` | Listening port for the decoy Boa RTSP camera trap |
| `HONEYPOT_DECOY_PROFILE` | `"realistic_iot"` | Decoy behavior profile |
| `HONEYPOT_HTTP_BANNER` | `"mini_httpd/1.30 01Jan2018"` | HTTP server header returned to scanners |
| `HONEYPOT_SSH_BANNER` | `"SSH-2.0-dropbear_2020.81"` | SSH daemon identification string |
| `HONEYPOT_CAMERA_BANNER` | `"Boa/0.94.14rc21"` | RTSP server header returned to scanners |

---

## 8. Windows PortProxy Setup Guide

To catch real attackers scanning standard ports on your local network (e.g., Nmap or Masscan scanning ports 80, 22, and 554), forward incoming traffic on privileged ports to your Cyber Home Shield honeypot listeners using the Windows built-in `netsh interface portproxy`.

### 1. Enable Port Forwarding (Run as Administrator in PowerShell):

```powershell
# Forward Port 80 (HTTP) to Honeypot Port 8088
netsh interface portproxy add v4tov4 listenport=80 listenaddress=0.0.0.0 connectport=8088 connectaddress=127.0.0.1

# Forward Port 22 (SSH) to Honeypot Port 2222
netsh interface portproxy add v4tov4 listenport=22 listenaddress=0.0.0.0 connectport=2222 connectaddress=127.0.0.1

# Forward Port 554 (RTSP Camera) to Honeypot Port 8554
netsh interface portproxy add v4tov4 listenport=554 listenaddress=0.0.0.0 connectport=8554 connectaddress=127.0.0.1
```

### 2. Allow Inbound Traffic in Windows Defender Firewall:

```powershell
New-NetFirewallRule -DisplayName "Cyber Home Shield - Honeypot Traps" -Direction Inbound -LocalPort 80,22,554,8088,2222,8554 -Protocol TCP -Action Allow
```

### 3. Verify Active PortProxy Rules:

```powershell
netsh interface portproxy show all
```

### 4. Teardown / Remove Rules (When Finished):

```powershell
netsh interface portproxy delete v4tov4 listenport=80 listenaddress=0.0.0.0
netsh interface portproxy delete v4tov4 listenport=22 listenaddress=0.0.0.0
netsh interface portproxy delete v4tov4 listenport=554 listenaddress=0.0.0.0
Remove-NetFirewallRule -DisplayName "Cyber Home Shield - Honeypot Traps"
```

> **Note**: Cyber Home Shield includes a **Port Proxy Helper** button directly in the Honeypot UI tab that automatically detects your local LAN IP and formats these exact commands for you.

---

## 9. Testing & Quality Verification

Cyber Home Shield maintains a strict, high-coverage testing regime across both the Python backend and TypeScript frontend:

```bash
# 1. Run all backend unit & integration tests (143+ tests passing)
pytest -q

# 2. Run honeypot and deception tests specifically
pytest tests/unit/test_honeypot_services.py tests/unit/test_honeypot_api.py -v

# 3. Verify TypeScript strict types without emit
npx tsc --noEmit

# 4. Build the production frontend distribution bundle
npm run build
```

---

## 10. Complete API Endpoint Reference

All endpoints are prefixed with `/api/v1`. Protected endpoints require a valid JWT Bearer token via `Authorization: Bearer <token>`.

### Authentication & Tenant Scoping
| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/auth/register` | Register new user with authorized RFC 1918 subnet scope | No |
| `POST` | `/auth/login` | Authenticate with email/password and receive JWT token | No |
| `GET` | `/auth/me` | Retrieve authenticated user profile and authorized CIDR | Yes |

### Device Inventory & Discovery
| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/devices` | List all discovered devices with MAC, IP, and open ports | Yes |
| `POST` | `/devices` | Manually register or tag a known network device | Yes |
| `GET` | `/devices/{id}` | Get detailed profile, open ports, and risk breakdown | Yes |
| `DELETE` | `/devices/{id}` | Remove device record from inventory | Yes |
| `GET` | `/scans` | List historical network discovery scan jobs | Yes |
| `POST` | `/scans` | Launch bounded RFC 1918 discovery scan across subnet | Yes |
| `GET` | `/scans/{id}` | Inspect progress and findings of active scan job | Yes |

### Deterministic Risk Engine
| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/risk/posture` | Calculate network-wide defensive posture score ($0-100$) | Yes |
| `GET` | `/risk/device/{id}` | Calculate deterministic risk breakdown for specific device | Yes |

### CipherX AI Threat Advisor
| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/ai/chat` | Interactive security chat with Llama 3.2 / Nemotron | Yes |
| `POST` | `/ai/triage` | Triage security finding or connection telemetry log | Yes |
| `POST` | `/ai/explain-device/{id}` | Generate narrative device vulnerability summary | Yes |
| `POST` | `/ai/explain-finding/{id}`| Generate step-by-step remediation guide for finding | Yes |
| `POST` | `/ai/hardening-guide` | Generate tailored hardening playbook for router/IoT | Yes |

### Deception & Honeypot Subsystem
| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/honeypot/status` | Get trap listener status, ports, banners, and LAN IP | Yes |
| `POST` | `/honeypot/start` | Activate multi-protocol honeypot trap listeners | Yes |
| `POST` | `/honeypot/stop` | Deactivate honeypot trap listeners | Yes |
| `GET` | `/honeypot/events` | List intercepted probe events with search & filters | Yes |
| `GET` | `/honeypot/events/{id}` | Retrieve raw intercepted probe event details | Yes |
| `POST` | `/honeypot/analyze/{id}` | Trigger AI threat analysis on intercepted probe | Yes |
| `POST` | `/honeypot/simulate` | Safely inject test probe (HTTP, SSH, RTSP) | Yes |

### Health & Telemetry
| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Subsystem health, DB connectivity, and runtime metrics | No |
| `GET` | `/telemetry/events` | Retrieve device connection telemetry events | Yes |
| `GET` | `/findings` | List security findings across all network endpoints | Yes |

---

## 11. Academic Presentation & Report Artifacts

For academic evaluations, thesis defenses, conference presentations, and technical documentation, a comprehensive presentation script and formal project report synopsis is included in the project repository:

📄 **[`project_presentation_and_synopsis.md`](./project_presentation_and_synopsis.md)**

This document contains:
1. **12-Slide Visual Presentation Script**: Complete with on-slide bullet points, visual diagram blueprints, speaker notes, and verbal speech scripts for project demonstrations.
2. **Formal Project Report Synopsis**: Structured academic overview containing Problem Statement, Objectives, Methodology, System Architecture, Mathematical Risk Model, Experimental Results, and Future Work.

---

## 12. Security Boundaries & Responsible Use

Cyber Home Shield is strictly engineered as a **defensive network monitoring and posture analysis tool**.

```text
  ┌─────────────────────────────────────────────────────────────┐
  │                 EXPLICIT DEFENSIVE BOUNDARIES               │
  ├─────────────────────────────────────────────────────────────┤
  │ ❌ No Offensive Exploits or Weaponized Payloads             │
  │ ❌ No Credential Harvesting, Cracking, or Brute-Forcing    │
  │ ❌ No Remote Arbitrary Command Execution                    │
  │ ❌ No Public WAN Scanning (RFC 1918 Scope Enforced)         │
  │ ❌ No Promiscuous Deep-Packet Inspection / Wiretapping      │
  │ ❌ No Automated Retaliation or Counter-Attacks              │
  └─────────────────────────────────────────────────────────────┘
```

- **Defensive Scope Only**: The platform does not exploit vulnerabilities, inject malicious payloads, or participate in distributed attacks.
- **Privacy First**: Sensitive credentials transmitted to honeypot traps are redacted immediately. Raw packet contents are never persisted or shared.
- **RFC 1918 Restriction**: Scanning targets must be within private IP spaces (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`). Scans targeting public Internet IPs are rejected with HTTP 422 errors.

---

## 13. License & Acknowledgments

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

### Acknowledgments
- **NVIDIA Corporation** for high-throughput AI inference via the [NVIDIA NIM API](https://build.nvidia.com/).
- **Meta AI** for the Llama 3.2 open-weights model family.
- **FastAPI** and **Pydantic** teams for Python async API tooling.
- **Tailwind Labs** and **Lucide** for UI design tokens and iconography.

---

<p align="center">
  <b>Cyber Home Shield &copy; 2026. Built with dedication for a safer, private, and resilient home Internet.</b>
</p>
