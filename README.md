# Cyber Home Shield (v1.0.0)

> **Defensive Home-Network Cybersecurity Platform**  
> Real-time RFC 1918 device discovery, deterministic risk scoring, statistical anomaly detection, isolated honeypot deception, and NVIDIA Nemotron AI threat advisory.

---

## 1. Project Overview & Defensive Philosophy

Cyber Home Shield is an ethical, defensive-only security operations platform engineered specifically for modern smart home and small-office local area networks. It empowers homeowners and network administrators to maintain total visibility over authorized LAN endpoints, detect lateral port probes early, compute mathematically verifiable risk scores, and receive actionable hardening guidance from an embedded **NVIDIA Nemotron Security Advisor**.

### Core Defensive Principles
1. **RFC 1918 Subnet Confinement**: Scanning, probing, and device mapping are strictly restricted to private address spaces (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and loopback `127.0.0.0/8`). Public WAN IPs, multicast, and broadcast ranges are categorically rejected.
2. **Deterministic Risk Scoring**: Risk values (0–100) are computed mathematically with sublinear scaling and clear evidence trails, ensuring repeatable posture assessments without hallucinations.
3. **Loopback-Isolated Honeypot Deception**: Decoy traps bind to `127.0.0.1` by default, execute zero system commands, proxy no traffic, and automatically redact credentials.
4. **Server-Side AI Privacy**: The NVIDIA Nemotron API key and prompts remain strictly server-side. No raw prompts, secrets, or reasoning traces are exposed to client browsers.

---

## 2. System Architecture

```text
                                 CYBER HOME SHIELD
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 │                                               │
           Real Devices                                       Honeypot
                 │                                               │
                 │                                         Fake Services
                 │                                         ├── HTTP (8088)
                 │                                         ├── SSH-like (2222)
                 │                                         └── Camera RTSP (8554)
                 │                                               │
                 └───────────────────────┬───────────────────────┘
                                         ↓
                                 Event Collector
                                         ↓
                                 Anomaly / Findings
                                         ↓
                                    Risk Engine
                                         ↓
                                  NVIDIA Nemotron
                                         ↓
                              AI Security Advisor (UI)
```

### Detailed Component Layering

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        React 18 Single-Page App                        │
│   Posture Dashboard | Device Inventory | Scanner | Findings | Traps   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP / JSON (JWT Bearer Auth)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        FastAPI Backend Engine                          │
│   ├── Authentication & RBAC (Argon2id + PyJWT)                         │
│   ├── RFC 1918 Scope Guard & Sliding-Window Rate Limiter              │
│   ├── Discovery Subsystem (Bounded concurrency, port profiling)        │
│   ├── Deterministic Risk Engine (Exposure + Vuln + Anomaly)            │
│   ├── Telemetry Baseline Tracker & Statistical Anomaly Engine          │
│   ├── Isolated Honeypot Manager (Loopback traps & Auto-Redaction)      │
│   └── NVIDIA Nemotron Client (Structured schema validation & fallback) │
└───────────────────────┬───────────────────────────────┬────────────────┘
                        │                               │
                        ▼                               ▼
    ┌───────────────────────────────┐       ┌───────────────────────┐
    │  PostgreSQL / Supabase DB     │       │ NVIDIA Nemotron API   │
    │  (AsyncPG + SQLAlchemy 2.0)   │       │ (nemotron-4-340b)     │
    └───────────────────────────────┘       └───────────────────────┘
```

---

## 3. Technology Stack

- **Backend**: Python 3.11+, FastAPI, SQLAlchemy 2.0 (async), Alembic, AsyncPG, Pydantic v2, PyJWT, Passlib (Argon2id), HTTPX.
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS, Lucide React, Recharts, Motion.
- **Database**: PostgreSQL (Production) / SQLite+aiosqlite (Unit Testing).
- **AI Engine**: NVIDIA Nemotron (`nemotron-4-340b-instruct` / `nemotron-3-8b`).

---

## 4. End-to-End Workflows

### Flow A — Registration & Multi-Tenant Isolation
1. User registers with email, password, and authorized subnet scope (e.g. `192.168.1.0/24`).
2. Passwords are securely hashed using Argon2id.
3. JWT access token is generated (HS256) with 24-hour expiration.
4. All device, scan, finding, and honeypot records enforce strict tenant `user_id` ownership checks (IDOR protected).

### Flow B — Defensive Network Discovery
1. Scans validate targets against the user's authorized RFC 1918 scope.
2. Concurrent socket probes profile safe discovery ports (e.g., 22, 53, 80, 443, 445, 554, 8080).
3. Non-intrusive service banners and MAC OUI vendor signatures are fingerprinted.
4. Discovery results are stored and linked to the authenticated user.

### Flow C — Deterministic Risk Engine
1. **Exposure Subscore**: Open ports, cleartext protocols (HTTP/Telnet/RTSP/SMB).
2. **Vulnerability Subscore**: Security findings scored by severity (CRITICAL=30, HIGH=15, MEDIUM=6, LOW=2, INFO=0). Sublinear dampening prevents score runaway.
3. **Anomaly Subscore**: Deviations from established 24-hour traffic baseline.
4. Total score is bounded $[0, 100]$ and yields a network-wide defensive posture rating.

### Flow D — Telemetry & Statistical Anomaly Baseline
1. Normal connection metadata is tracked across destination ports, protocols, and event rates.
2. Sudden packet surges, rapid unknown port deviations, or connection bursts trigger anomaly findings.
3. Anomaly findings feed directly into device and network posture risk calculations.

### Flow E & F — NVIDIA Nemotron AI Threat Advisor & Fallback
1. Telemetry and findings are sanitized (no passwords/tokens) and sent to NVIDIA Nemotron.
2. Responses are validated against strict JSON schemas (Summary, Observed Facts, Recommendations, Confidence).
3. **Graceful Fallback**: If the NVIDIA API key is omitted or the service is offline, a deterministic, rule-based fallback response is provided. The application never crashes.

### Flow G — Honeypot & Deception Subsystem
1. Subsystem defaults to disabled (`HONEYPOT_ENABLED=false`) and loopback only (`HONEYPOT_BIND_HOST=127.0.0.1`).
2. Active traps:
   - **IoT Gateway Trap** (Port 8088 / HTTP): Emulates smart hub authentication.
   - **SSH Decoy Trap** (Port 2222 / TCP): Serves SSH-2.0 banner; zero shell access.
   - **IP Camera Trap** (Port 8554 / TCP): Simulates RTSP snapshot queries.
3. Injected probes trigger defensive telemetry, logged with auto-redacted payloads (`[REDACTED]`).

---

## 5. Local Setup & Startup Guide

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- PostgreSQL 14+ (or SQLite for testing)

### Step 1: Clone and Configure Environment
```bash
cp .env.example .env
cp backend/.env.example backend/.env
```

Edit `.env` to configure your PostgreSQL connection string and optional `NVIDIA_API_KEY`:
```env
DATABASE_URL="postgresql+asyncpg://postgres:postgres@localhost:5432/cyber_home_shield"
SECRET_KEY="your-secure-random-32-character-secret-key"
NVIDIA_API_KEY="your-nvidia-nim-api-key"
```

### Step 2: Backend Setup & Migrations
```bash
# Setup Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install backend dependencies
pip install -r backend/requirements.txt

# Run Alembic database migrations
alembic upgrade head

# Start FastAPI development server
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Step 3: Frontend Setup & Startup
```bash
# Install frontend packages
npm install

# Start Vite frontend dev server (binds to http://localhost:3000)
npm run dev
```

---

## 6. Testing & Quality Verification

Run the full verification suite across backend and frontend:

```bash
# 1. Run full backend unit & integration tests (143 tests)
pytest -q

# 2. Run TypeScript strict type verification
npx tsc --noEmit

# 3. Build production frontend bundle
npm run build
```

---

## 7. Complete API Endpoint Inventory

| Method | Endpoint | Purpose | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Subsystem health & status check | No |
| `POST` | `/api/v1/auth/register` | User account registration & subnet scope assignment | No |
| `POST` | `/api/v1/auth/login` | Authentication & JWT token issuance | No |
| `GET` | `/api/v1/auth/me` | Current authenticated user profile | Bearer Token |
| `GET` | `/api/v1/devices` | List authorized network devices (with filters) | Bearer Token |
| `POST` | `/api/v1/devices` | Register new device manually | Bearer Token |
| `GET` | `/api/v1/devices/{device_id}` | Retrieve specific device details & open ports | Bearer Token |
| `DELETE` | `/api/v1/devices/{device_id}` | Delete device record | Bearer Token |
| `GET` | `/api/v1/scans` | List historical discovery scan jobs | Bearer Token |
| `POST` | `/api/v1/scans` | Initiate targeted RFC 1918 discovery scan | Bearer Token |
| `GET` | `/api/v1/scans/{scan_id}` | Check status and results of scan job | Bearer Token |
| `GET` | `/api/v1/risk/posture` | Calculate aggregate network risk posture | Bearer Token |
| `GET` | `/api/v1/risk/device/{device_id}` | Calculate deterministic device risk score | Bearer Token |
| `POST` | `/api/v1/ai/chat` | Chat with NVIDIA Nemotron AI Advisor | Bearer Token |
| `POST` | `/api/v1/ai/triage` | Triage security finding or connection telemetry | Bearer Token |
| `POST` | `/api/v1/ai/explain-device/{device_id}` | Generate narrative device risk breakdown | Bearer Token |
| `POST` | `/api/v1/ai/explain-finding/{finding_id}` | Generate step-by-step remediation guide | Bearer Token |
| `POST` | `/api/v1/ai/hardening-guide` | Generate tailored device hardening playbook | Bearer Token |
| `GET` | `/api/v1/honeypot/status` | Retrieve deception subsystem status & active traps | Bearer Token |
| `POST` | `/api/v1/honeypot/start` | Activate loopback honeypot trap listeners | Bearer Token |
| `POST` | `/api/v1/honeypot/stop` | Deactivate honeypot trap listeners | Bearer Token |
| `GET` | `/api/v1/honeypot/events` | List intercepted probe events (with filters) | Bearer Token |
| `GET` | `/api/v1/honeypot/events/{event_id}` | Get detailed honeypot event telemetry | Bearer Token |
| `POST` | `/api/v1/honeypot/analyze/{event_id}` | Trigger Nemotron analysis of honeypot probe | Bearer Token |
| `POST` | `/api/v1/honeypot/simulate` | Safely inject test probe for triage verification | Bearer Token |

---

## 8. Production Deployment Architecture

- **Frontend**: Deploy static bundle (`dist/`) to Vercel, Cloudflare Pages, or AWS S3 + CloudFront with HTTPS.
- **Backend**: Deploy FastAPI container behind an NGINX reverse proxy on Cloud Run, AWS ECS, or Render with TLS termination.
- **Database**: Managed PostgreSQL (Supabase or AWS RDS) with SSL connection pooling.
- **Honeypot Policy**: In production, the honeypot subsystem MUST remain bound to `127.0.0.1` or dedicated isolated VLANs (802.1Q). It must **never** be exposed directly to the public Internet without deliberate DMZ isolation.

---

## 9. Security Boundaries & Limitations

Cyber Home Shield is strictly a **defensive network monitoring and posture analysis engine**.

### Prohibited / Non-Supported Capabilities
- **No Offensive Exploitation**: The platform does not launch weaponized exploits or vulnerability payloads.
- **No Credential Harvesting / Cracking**: The platform does not brute-force passwords or store intercepted credentials.
- **No Arbitrary Command Execution**: Decoy services and scanners cannot execute remote system binaries or shell scripts.
- **No WAN Scanning**: Scans targeting non-RFC1918 public IP addresses are blocked at the schema validation layer.
- **No Unrestricted Packet Capture**: Does not perform promiscuous deep-packet inspection or invasive traffic tampering.
- **No Autonomous Retaliation**: Defenses are purely advisory and preventative.

---

## 10. License

Released under the MIT License for defensive and educational home-network security operations.
