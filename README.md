<div align="center">

# Vigil

**Smart API protection middleware with fingerprint tracking and pattern detection.**

Vigil sits between the internet and your API, analyzes every incoming request in under 3 milliseconds, and decides whether to allow, challenge, or block it — based on behavioral fingerprinting and statistical pattern detection.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-3776AB.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688.svg)](https://fastapi.tiangolo.com)
[![Redis](https://img.shields.io/badge/Redis-DC382D.svg)](https://redis.io)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1.svg)](https://postgresql.org)

</div>

---

## What is Vigil

Most API security tools offer two options: expensive enterprise products or basic rate limiting by IP address. Neither stops a real attacker who rotates through hundreds of proxy IPs.

Vigil solves this by fingerprinting the **HTTP client itself** — not just the IP address. An attacker using 500 different IPs but the same Python script produces the same fingerprint every time. One fingerprint, one block, attack over.

---

## How It Works

Vigil runs on a **three-speed detection architecture**:

| Speed | Runs | Latency | What It Does |
|---|---|---|---|
| **Fast Path** | Every request | < 3ms | Fingerprint extraction, blocklist/allowlist checks, velocity tracking, cached threat score lookup |
| **Background Worker** | Every 3 seconds | ~50ms | Pattern detection (enumeration, credential stuffing), anomaly detection (z-score), threat scoring (6 weighted signals) |
| **AI Analysis** | Confirmed attacks only | 2–5s | Human-readable attack explanation using Google Gemini. Falls back to deterministic templates when AI is unavailable |

The fast path handles the real-time decision. The background worker handles the intelligence. They communicate through Redis — the worker updates cached scores that the fast path reads on the next request.

---

## Tech Stack

| Layer | Technology |
|---|---|
| API Framework | Python 3.12, FastAPI, Uvicorn |
| Cache & Streams | Redis 7 (sorted sets, streams, pub/sub) |
| Database | PostgreSQL 16 (window functions, partial indexes, JSONB) |
| Dashboard | React, TypeScript, Tailwind CSS, Vite |
| AI Analysis | Google Gemini 1.5 Flash (optional) |
| Infrastructure | Docker Compose |
| Testing | pytest, Locust (load testing) |

---

## Architecture

![Vigil Architecture](docs/architecture.png)

**Redis is used in 6 different ways:** blocklist lookups, allowlist lookups, velocity tracking (sorted sets), threat score caching, event streaming (Redis Streams with consumer groups), and live dashboard feed (Pub/Sub).

**PostgreSQL** handles permanent storage with composite indexes, partial indexes on suspicious requests, window functions for analytics, and `FILTER` clauses for conditional aggregation.

For detailed technical documentation, see [`docs/DOCUMENTATION.md`](docs/DOCUMENTATION.md).

---

## Features

- **Behavioral Fingerprinting** — Identifies clients by HTTP header signatures (User-Agent, Accept-Encoding, Accept-Language, sec-ch-ua), not just IP address
- **Enumeration Detection** — Catches sequential resource scanning using coefficient of variation on path suffixes
- **Credential Stuffing Detection** — Triple-signal detection: auth endpoint concentration + failure rate + body hash uniqueness
- **Statistical Anomaly Detection** — Trimmed z-scores against population velocity + interval regularity analysis
- **Threat Scoring** — 6 weighted signals with pattern confidence override and exponential time decay
- **Cold Start Manager** — Graduated thresholds (learning → cautious → normal) to prevent false positives on fresh deployments
- **Real-Time Dashboard** — Live WebSocket feed, attack sessions, fingerprint management, analytics charts
- **AI Attack Analysis** — Gemini-powered explanations for confirmed attacks (optional, falls back gracefully)
- **Horizontal Scaling** — Redis consumer groups distribute events across multiple workers with no duplicates

---

## Setup

### Prerequisites

- Python 3.12+
- Node.js 18+ (for dashboard)
- Docker & Docker Compose (for PostgreSQL and Redis)

### Step 1 — Clone the Repository

```bash
git clone https://github.com/your-username/vigil.git
cd vigil
```

### Step 2 — Start Infrastructure

```bash
docker-compose up -d
```

This starts PostgreSQL (port 5432) and Redis (port 6500).

### Step 3 — Set Up Environment

```bash
cp .env.example .env
```

Edit `.env` with your configuration. The defaults work with the Docker Compose setup:

```env
DATABASE_URL=postgresql+asyncpg://Vigil:Vigil@localhost:5432/Vigil
DATABASE_URL_SYNC=postgresql://Vigil:Vigil@localhost:5432/Vigil
REDIS_URL=redis://localhost:6500
GEMINI_API_KEY=your_gemini_api_key_here   # optional
DEBUG=true
```

### Step 4 — Install Dependencies

```bash
python -m venv venv
source venv/bin/activate        # Linux/Mac
# venv\Scripts\activate         # Windows

pip install -r requirements.txt
```

### Step 5 — Run Database Migrations

```bash
alembic upgrade head
```

### Step 6 — Start the API Server

```bash
uvicorn Vigil.main:app --host 0.0.0.0 --port 8000 --reload
```

### Step 7 — Start the Background Worker

In a separate terminal:

```bash
python -m Vigil.workers.stream_consumer
```

### Step 8 — Start the Dashboard (optional)

```bash
cd dashboard
cp .env.example .env
npm install
npm run dev
```

Dashboard will be available at `http://localhost:5173`.

### Verify Everything Works

```bash
# Health check
curl http://localhost:8000/health

# Send a test request
curl -X POST http://localhost:8000/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"method": "GET", "path": "/api/test"}'
```

Or generate demo data with attacks:

```bash
python scripts/seed_data.py
python scripts/verify_detection.py
```

---

## Integration

Vigil integrates in **one API call**. Add it to your middleware — every request passes through Vigil before reaching your application logic:

```python
import httpx

async def vigil_middleware(request, call_next):
    # Forward the request to Vigil for analysis (< 3ms)
    async with httpx.AsyncClient() as client:
        result = await client.post(
            "http://localhost:8000/v1/analyze",
            json={
                "method": request.method,
                "path": str(request.url.path),
            },
            headers=dict(request.headers),  # forward client headers for fingerprinting
        )
        decision = result.json()

    if decision["action"] == "block":
        return JSONResponse(status_code=403, content={"error": "blocked"})

    return await call_next(request)
```

The key is forwarding the original client's HTTP headers — Vigil needs them for fingerprinting.

---

## Screenshots

<div align="center">

### Dashboard Overview
![Dashboard Overview](docs/dashboard-overview.png)

### Attack Detection & AI Analysis
![Attack Details](docs/dashboard-attacks.png)

### Analytics & Score Distribution
![Analytics](docs/dashboard-analytics.png)

</div>

---

## Project Structure

```
vigil/
├── Vigil/                      # Core Python package
│   ├── api/                    # FastAPI route handlers
│   │   ├── analyze.py          # POST /v1/analyze — core endpoint
│   │   ├── analytics.py        # Analytics queries (PostgreSQL)
│   │   ├── attacks.py          # Attack session endpoints
│   │   ├── feedback.py         # Detection feedback
│   │   ├── fingerprints.py     # Fingerprint management
│   │   ├── middleware.py       # Rate limiting on Vigil's own API
│   │   └── websocket.py       # Live feed WebSocket
│   ├── core/                   # Detection algorithms
│   │   ├── anomaly.py          # Z-score + interval regularity
│   │   ├── circuit_breaker.py  # Fault tolerance
│   │   ├── cold_start.py       # Graduated thresholds
│   │   ├── decisions.py        # Decision engine
│   │   ├── event_logger.py     # Redis Stream logging
│   │   ├── fast_path.py        # < 3ms request analysis
│   │   ├── fingerprinting.py   # HTTP header fingerprinting
│   │   ├── ip_extraction.py    # Real IP through proxies
│   │   ├── patterns.py         # Enumeration + credential stuffing
│   │   ├── scoring.py          # 6-signal threat scoring
│   │   └── velocity.py         # Sliding window rate tracking
│   ├── cache/                  # Redis client
│   ├── db/                     # PostgreSQL models + migrations
│   ├── workers/                # Background processing
│   │   ├── ai_analyst.py       # Gemini AI integration
│   │   └── stream_consumer.py  # Redis Stream consumer
│   ├── config.py               # Settings + structured logging
│   └── main.py                 # FastAPI app entry point
├── dashboard/                  # React dashboard (TypeScript)
├── tests/
│   ├── unit/                   # Unit tests (9 test files)
│   ├── integration/            # Full pipeline tests
│   └── load/                   # Locust load tests
├── scripts/
│   ├── seed_data.py            # Generate demo traffic + attacks
│   └── verify_detection.py     # Verify detection accuracy
├── docs/                       # Architecture diagram + documentation
├── docker-compose.yml          # PostgreSQL + Redis
├── requirements.txt            # Python dependencies
├── requirements-dev.txt        # Testing + code quality tools
├── alembic.ini                 # Database migration config
└── LICENSE
```

---

## License

This project is licensed under the [MIT License](LICENSE).
