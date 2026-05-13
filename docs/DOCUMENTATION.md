# Vigil — Technical Documentation

## Table of Contents

- [System Architecture](#system-architecture)
- [Three-Speed Detection System](#three-speed-detection-system)
- [Fingerprinting](#fingerprinting)
- [IP Extraction](#ip-extraction)
- [Velocity Tracking](#velocity-tracking)
- [Pattern Detection Algorithms](#pattern-detection-algorithms)
- [Anomaly Detection](#anomaly-detection)
- [Threat Scoring](#threat-scoring)
- [Cold Start Manager](#cold-start-manager)
- [Background Worker](#background-worker)
- [Database Design](#database-design)
- [Redis Usage](#redis-usage)
- [API Reference](#api-reference)

---

## System Architecture

Vigil operates as a middleware service that sits between the internet and your API. Every incoming request is analyzed in under 3 milliseconds, and a decision is returned: **allow**, **block**, or **challenge**.

```
Internet → Business API → Vigil Fast Path (< 3ms) → Decision
                                  ↓
                            Redis Stream
                                  ↓
                         Background Worker (every 3s)
                           ↓              ↓
                        Redis           PostgreSQL
                     (scores)          (permanent logs)
                                          ↓
                                    React Dashboard
```

See `docs/architecture.png` for the full architecture diagram.

---

## Three-Speed Detection System

The architecture is split into three processing tiers, each optimized for different latency requirements:

### Speed 1 — Fast Path (every request, < 3ms)

Only checks pre-computed, cached values in Redis. No database calls, no heavy computation.

- Extract fingerprint from HTTP headers
- Check blocklist / allowlist
- Record and check velocity (requests per minute)
- Read cached threat score
- Make decision: allow / block / challenge
- Log event to Redis Stream (async)

**File:** `Vigil/core/fast_path.py`

### Speed 2 — Background Worker (every 3 seconds)

Reads events from the Redis Stream, accumulates per-fingerprint history, and runs all detection algorithms:

- Pattern detection (enumeration, credential stuffing)
- Statistical anomaly detection (z-score, interval regularity)
- Threat score computation (6 weighted signals)
- Time decay on scores
- Auto-blocking when threshold is exceeded

**File:** `Vigil/workers/stream_consumer.py`

### Speed 3 — AI Analysis (confirmed attacks only)

Only triggered when a confirmed attack pattern is detected. Uses Google Gemini to generate human-readable explanations. Falls back to deterministic templates when AI is unavailable.

**File:** `Vigil/workers/ai_analyst.py`

---

## Fingerprinting

Vigil identifies clients by their HTTP behavioral signature rather than IP address alone. This defeats IP rotation attacks.

### Four Signals

| Signal | Why It Works |
|---|---|
| `User-Agent` | Identifies the software making the request |
| `Accept-Encoding` | Set by the HTTP library, not the user |
| `Accept-Language` | Scripts don't have a language preference |
| `sec-ch-ua` | Only Chrome/Edge send this; catches faked User-Agents |

### Hash Computation

```python
components = [user_agent, accept_language, accept_encoding, sec_ch_ua]
raw = "|".join(components)
fingerprint_hash = hashlib.sha256(raw.encode()).hexdigest()[:16]
```

The first 16 hex characters (64 bits) give 18 quintillion possible fingerprints — collision probability is negligible at any practical scale.

### Confidence Score

```
signals_present / total_signals
```

- 4/4 signals → confidence 1.0
- 3/4 signals → confidence 0.75
- 0/4 signals → confidence 0.0 (effectively just an IP address)

**File:** `Vigil/core/fingerprinting.py`

---

## IP Extraction

Real client IP extraction through proxy chains:

```
Priority 1: CF-Connecting-IP  (Cloudflare — most trusted)
Priority 2: X-Real-IP         (nginx standard)
Priority 3: X-Forwarded-For   (rightmost untrusted IP)
Priority 4: request.client.host (direct connection)
```

The rightmost non-trusted IP in `X-Forwarded-For` is used because leftmost entries can be spoofed by attackers.

**File:** `Vigil/core/ip_extraction.py`

---

## Velocity Tracking

Uses Redis Sorted Sets with timestamps as scores for a true sliding window rate counter.

```python
pipe = redis.pipeline(transaction=False)
pipe.zadd(key, {member: now})           # add this request
pipe.zremrangebyscore(key, 0, now-3600) # clean old data
pipe.zcount(key, now-60, now)           # count last 1 min
pipe.zcount(key, now-300, now)          # count last 5 min
pipe.zcount(key, now-3600, now)         # count last 1 hour
pipe.expire(key, 7200)                  # auto-delete after 2h
results = await pipe.execute()          # one network round-trip
```

All 6 Redis commands execute in a single pipeline — one network round-trip instead of six.

**File:** `Vigil/core/velocity.py`

---

## Pattern Detection Algorithms

### Enumeration Detection

Detects sequential resource scanning (e.g., `/api/users/1`, `/api/users/2`, ...).

1. Filter out pagination patterns to prevent false positives
2. Extract numeric suffixes and group by base path
3. Compute coefficient of variation (CV) on consecutive differences
4. CV < 0.3 with 5+ sequential paths → enumeration detected
5. Check timing regularity (bot-like consistent intervals)

### Credential Stuffing Detection

Requires **all three signals** to be true simultaneously:

| Signal | Threshold | Rationale |
|---|---|---|
| Auth endpoint concentration | > 60% | Most requests target login endpoints |
| Failure rate | > 50% | More than half of auth attempts fail (401/403) |
| Body hash uniqueness | > 50% | Different credentials on each attempt |

Any single signal alone could be legitimate. All three together is strong evidence.

**File:** `Vigil/core/patterns.py`

---

## Anomaly Detection

### Trimmed Z-Score

Measures how far a fingerprint's velocity deviates from the population average. Uses 5% trimming to prevent attackers from skewing the baseline.

```
Z = (fingerprint_velocity - trimmed_mean) / trimmed_std_dev
```

Minimum 20 data points required before z-scores are computed.

### Interval Regularity

Measures timing consistency between requests. Bots send at fixed intervals (CV ≈ 0); humans are irregular (CV > 1).

```
regularity = max(0, min(1, 1 - (cv / 2)))
```

**File:** `Vigil/core/anomaly.py`

---

## Threat Scoring

Six signals, each normalized to 0.0–1.0, combined with weighted sum:

| Signal | Weight | Normalization |
|---|---|---|
| Velocity | 0.20 | Linear: RPM / hard_limit |
| Pattern | 0.30 | Direct (already 0–1) |
| Anomaly | 0.20 | Sigmoid: 1/(1 + e^-(z-2)) |
| Regularity | 0.10 | Direct (already 0–1) |
| IP Diversity | 0.10 | Logarithmic: log2(count) / 6 |
| History | 0.10 | Linear: past_blocks / 5 |

### Pattern Confidence Override

High-confidence pattern matches override the aggregate score to prevent slow, careful attackers from evading detection:

- Pattern confidence > 0.95 → minimum score 0.85 (block)
- Pattern confidence > 0.85 → minimum score 0.70 (challenge)

### Time Decay

Scores decay exponentially with a 1-hour half-life:

```
decayed = score × e^(-0.693 × age_seconds / 3600)
```

After 1 hour: 50%. After 2 hours: 25%. After 6 hours: ~1.6%.

**File:** `Vigil/core/scoring.py`

---

## Cold Start Manager

Handles the bootstrap problem — Vigil has zero data when first deployed.

| Phase | Duration | Block Threshold | Velocity Limit |
|---|---|---|---|
| Learning | 0–1 hour | 0.95 | 500 RPM |
| Cautious | 1–24 hours | 0.85 | 300 RPM |
| Normal | 24+ hours | 0.85 | 200 RPM |

Start time is persisted to Redis to prevent restart exploits.

**File:** `Vigil/core/cold_start.py`

---

## Background Worker

Consumes events from a Redis Stream using consumer groups for horizontal scaling.

### Processing Pipeline (per batch, every 3 seconds)

1. Read up to 100 events from stream
2. Group events by fingerprint
3. For each fingerprint:
   - Accumulate history in Redis list (last 200 events)
   - Run pattern detection
   - Run anomaly detection
   - Compute threat score
   - Apply time decay
   - Update cached score in Redis
   - Auto-block if above threshold
   - Create attack session if pattern confirmed (with AI analysis)
4. Batch write all events to PostgreSQL
5. Acknowledge processed messages
6. Publish to live dashboard feed (Redis Pub/Sub)

### Horizontal Scaling

Consumer groups ensure each event is processed by exactly one worker. Multiple workers can run in parallel with no duplicates.

**File:** `Vigil/workers/stream_consumer.py`

---

## Database Design

### Seven Tables

| Table | Purpose |
|---|---|
| `organizations` | Multi-tenant support (V1 uses single default org) |
| `api_keys` | API authentication (key hashes, not plain text) |
| `fingerprints` | Permanent record of each device identity |
| `fingerprint_ips` | IP addresses associated with each fingerprint |
| `requests` | Every request analyzed (largest table) |
| `attack_sessions` | Confirmed attacks with AI analysis |
| `feedback` | Human corrections for accuracy tracking |

### Key Design Decisions

- **`requests.fingerprint_hash`** is a string, not a foreign key — because fingerprints are created asynchronously by the background worker
- **Partial index** on `is_suspicious` — only indexes suspicious rows (~5% of data), making the index 20x smaller
- **Composite indexes** on `(fingerprint_hash, created_at)` and `(org_id, created_at)` for range queries

### SQL Features Used

- `FILTER` clause for conditional aggregation in one pass
- `date_trunc` for time-bucketed grouping
- Window functions (`SUM() OVER()`) for percentage calculations
- `CASE` expressions for histogram buckets
- `COALESCE` + `NULLIF` for safe division

**File:** `Vigil/db/models.py`

---

## Redis Usage

Redis serves six distinct roles in Vigil:

| Role | Key Pattern | Data Structure |
|---|---|---|
| Blocklist | `blocked:{hash}` | String (reason) |
| Allowlist | `allowed:{hash}` | String |
| Velocity | `velocity:{hash}` | Sorted Set (timestamps) |
| Threat Scores | `threat:{hash}` | String (float) |
| Event Stream | `vigil:request_events` | Stream |
| Live Feed | `vigil:live_feed` | Pub/Sub channel |

Additional keys: `history:{hash}` (List), `ips:{hash}` (Set), `vigil:cold_start_time` (String).

---

## API Reference

### Core Endpoint

```
POST /v1/analyze
```

Send request metadata, receive a decision in < 3ms.

**Request:**
```json
{
  "method": "GET",
  "path": "/api/users/42",
  "status_code": 200,
  "body_hash": "a1b2c3d4e5f6g7h8"
}
```

**Response:**
```json
{
  "action": "allow",
  "reason": "below thresholds",
  "threat_score": 0.12,
  "fingerprint": "07ea71439bb3ab15",
  "velocity_rpm": 3,
  "phase": "normal"
}
```

### Analytics Endpoints

| Endpoint | Description |
|---|---|
| `GET /v1/analytics/overview` | Key metrics (total, blocked, allowed, block rate) |
| `GET /v1/analytics/timeline` | Hourly traffic breakdown |
| `GET /v1/analytics/top-threats` | Top fingerprints by threat score |
| `GET /v1/analytics/attack-type-distribution` | Attack type breakdown |
| `GET /v1/analytics/top-targeted-endpoints` | Most attacked paths |
| `GET /v1/analytics/score-distribution` | Threat score histogram |
| `GET /v1/analytics/fingerprint/{hash}/history` | Per-fingerprint timeline |

### Management Endpoints

| Endpoint | Description |
|---|---|
| `GET /v1/fingerprints` | List all known fingerprints |
| `POST /v1/fingerprints/{hash}/block` | Block a fingerprint |
| `POST /v1/fingerprints/{hash}/allowlist` | Allowlist a fingerprint |
| `DELETE /v1/fingerprints/{hash}/block` | Unblock a fingerprint |
| `GET /v1/attacks` | List detected attack sessions |
| `GET /v1/attacks/{id}` | Attack session details |
| `POST /v1/feedback` | Submit detection accuracy feedback |

### WebSocket

```
WS /ws/live-feed
```

Real-time event stream for the dashboard. Events are published via Redis Pub/Sub.

### Health Check

```
GET /health
```

Returns `{"status": "healthy", "service": "Vigil"}` if the server is running.
