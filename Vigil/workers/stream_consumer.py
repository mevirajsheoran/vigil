"""
Background worker — consumes Redis Stream, runs detection.

HOW IT WORKS:
1. Every 3 seconds, read events from Redis Stream
2. Group events by fingerprint
3. For each fingerprint:
   a. Store events in per-fingerprint history (Redis list)
   b. Read full history (last 200 events)
   c. Run pattern detection on history
   d. Run anomaly detection
   e. Compute threat score
   f. Update cached score in Redis
   g. If attack detected → create AttackSession in PostgreSQL
   h. If attack detected → call AI analyst
4. Batch write all events to PostgreSQL request logs
5. Acknowledge processed messages
6. Publish events to live dashboard feed

HORIZONTAL SCALING:
Consumer groups ensure each event is processed by exactly
ONE worker. docker-compose runs 2 replicas automatically.

HOW TO RUN:
  python -m Vigil.workers.stream_consumer
"""

import asyncio
import json
import os
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone

import redis.asyncio as aioredis
from sqlalchemy import select

from Vigil.config import settings, logger
from Vigil.core.patterns import detect_all_patterns
from Vigil.core.anomaly import detect_anomaly
from Vigil.core.scoring import (
    ThreatSignals,
    compute_threat_score,
    apply_time_decay,
)
from Vigil.core.event_logger import STREAM_KEY
from Vigil.db.engine import async_session
from Vigil.db.models import (
    Request as RequestModel,
    Fingerprint,
    AttackSession,
    DEFAULT_ORG_ID,
)
from Vigil.workers.ai_analyst import analyze_attack

BATCH_SIZE = 100
GROUP_NAME = "vigil_workers"
CONSUMER_NAME = os.environ.get(
    "WORKER_ID", f"worker_{os.getpid()}"
)


async def ensure_consumer_group(
    redis_client: aioredis.Redis,
) -> None:
    """
    Create consumer group if it doesn't exist.

    Consumer group = a named group of workers that
    share the stream. Events are distributed among
    workers in the group — no duplicates.

    BUSYGROUP error means the group already exists — safe to ignore.
    """
    try:
        await redis_client.xgroup_create(
            STREAM_KEY, GROUP_NAME,
            id="0", mkstream=True,
        )
    except aioredis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


async def process_events(
    redis_client: aioredis.Redis,
) -> None:
    """
    Main processing loop — read events, analyze, update.

    Called every 3 seconds by the worker loop.
    """
    # Read events from stream
    results = await redis_client.xreadgroup(
        GROUP_NAME,
        CONSUMER_NAME,
        {STREAM_KEY: ">"},  # ">" means unread messages
        count=BATCH_SIZE,
        block=2000,  # Wait up to 2 seconds for new events
    )

    if not results:
        return

    # Collect all events and group by fingerprint
    fingerprint_events: dict[str, list[dict]] = defaultdict(
        list
    )
    message_ids: list[str] = []
    all_events: list[dict] = []

    for stream_name, messages in results:
        for msg_id, data in messages:
            message_ids.append(msg_id)
            fp = data.get("fingerprint", "unknown")
            fingerprint_events[fp].append(data)
            all_events.append(data)

    # Get population velocities ONCE per batch
    # (used by anomaly detection for z-score)
    population_velocities = (
        await _get_population_velocities(redis_client)
    )

    # Analyze each fingerprint
    for fp_hash, events in fingerprint_events.items():
        await _analyze_fingerprint(
            redis_client,
            fp_hash,
            events,
            population_velocities,
        )

    # Batch write to PostgreSQL
    await _batch_write_to_postgres(all_events)

    # Acknowledge processed messages
    if message_ids:
        await redis_client.xack(
            STREAM_KEY, GROUP_NAME, *message_ids
        )


async def _analyze_fingerprint(
    redis_client: aioredis.Redis,
    fingerprint_hash: str,
    recent_events: list[dict],
    population_velocities: list[float],
) -> None:
    """Run all detection algorithms on one fingerprint."""

    # ── Step 1: Accumulate history ──
    # Store events in per-fingerprint Redis list
    # This allows pattern detection to see 200+ events
    # across multiple worker cycles
    history_key = f"history:{fingerprint_hash}"

    for event in recent_events:
        await redis_client.rpush(
            history_key,
            json.dumps({
                "path": event.get("path", "/"),
                "method": event.get("method", "GET"),
                "timestamp": event.get(
                    "timestamp", str(time.time())
                ),
                "status_code": event.get(
                    "status_code", "0"
                ),
                "body_hash": event.get("body_hash", ""),
                "ip": event.get("ip", ""),
            }),
        )

    # Keep only last 200 events (trim from left)
    await redis_client.ltrim(history_key, -200, -1)
    await redis_client.expire(history_key, 3600)

    # ── Step 2: Read full history ──
    raw_history = await redis_client.lrange(
        history_key, 0, -1
    )
    history = [json.loads(h) for h in raw_history]

    if not history:
        return

    # Extract fields for detection algorithms
    paths = [h["path"] for h in history]
    methods = [h["method"] for h in history]
    timestamps = [float(h["timestamp"]) for h in history]
    status_codes = [int(h["status_code"]) for h in history]
    body_hashes = [
        h["body_hash"] if h["body_hash"] else None
        for h in history
    ]

    # ── Step 3: Current velocity ──
    velocity_key = f"velocity:{fingerprint_hash}"
    now = time.time()
    current_rpm = await redis_client.zcount(
        velocity_key, now - 60, now
    )

    # ── Step 4: Pattern detection ──
    pattern_result = detect_all_patterns(
        paths, methods, timestamps,
        status_codes, body_hashes,
    )
    pattern_confidence = (
        pattern_result.confidence
        if pattern_result
        else 0.0
    )

    # ── Step 5: Anomaly detection ──
    anomaly_result = detect_anomaly(
        fingerprint_velocity=float(current_rpm),
        population_velocities=population_velocities,
        timestamps=timestamps,
    )

    # ── Step 6: IP diversity ──
    ip_set_key = f"ips:{fingerprint_hash}"
    for event in recent_events:
        ip = event.get("ip", "")
        if ip:
            await redis_client.sadd(ip_set_key, ip)
            await redis_client.expire(ip_set_key, 86400)
    distinct_ips = await redis_client.scard(ip_set_key)

    # ── Step 7: Historical blocks ──
    blocks_key = f"blocks:{fingerprint_hash}"
    historical_blocks = int(
        await redis_client.get(blocks_key) or 0
    )

    # ── Step 8: Compose threat score ──
    signals = ThreatSignals(
        velocity_rpm=float(current_rpm),
        velocity_hard_limit=float(
            settings.velocity_hard_limit
        ),
        pattern_confidence=pattern_confidence,
        zscore=anomaly_result.zscore,
        regularity_score=anomaly_result.regularity_score,
        distinct_ip_count=distinct_ips,
        historical_blocks=historical_blocks,
    )
    threat = compute_threat_score(signals)

    # ── Step 9: Time decay ──
    last_suspicious = await redis_client.get(
        f"last_suspicious:{fingerprint_hash}"
    )
    if last_suspicious and threat.score < 0.5:
        final_score = apply_time_decay(
            threat.score, float(last_suspicious)
        )
    else:
        final_score = threat.score

    # ── Step 10: Update Redis ──
    await redis_client.setex(
        f"threat:{fingerprint_hash}",
        3600,
        str(round(final_score, 4)),
    )

    # Track active fingerprints in sorted set (for dashboard)
    await redis_client.zadd(
        "vigil:active_fingerprints",
        {fingerprint_hash: final_score},
    )

    if final_score > 0.5:
        await redis_client.setex(
            f"last_suspicious:{fingerprint_hash}",
            86400,
            str(time.time()),
        )

    # ── Step 11: Auto-block if score exceeds threshold ──
    if final_score >= settings.block_threshold:
        reason = (
            f"threat_score={final_score:.2f}, "
            f"pattern="
            f"{pattern_result.pattern_type if pattern_result else 'none'}"
        )
        await redis_client.setex(
            f"blocked:{fingerprint_hash}",
            3600,
            reason,
        )
        await redis_client.incr(blocks_key)
        await redis_client.expire(blocks_key, 86400)

    # ── Step 12: Create AttackSession if pattern detected ──
    if (
        pattern_result
        and pattern_result.confidence > 0.7
    ):
        await _create_attack_session(
            fingerprint_hash=fingerprint_hash,
            pattern_result=pattern_result,
            recent_events=recent_events,
            distinct_ips=distinct_ips,
        )

    # ── Step 13: Publish to live dashboard ──
    last_event = recent_events[-1]
    await redis_client.publish(
        "vigil:live_feed",
        json.dumps({
            "fingerprint": fingerprint_hash,
            "ip": last_event.get("ip", ""),
            "method": last_event.get("method", ""),
            "path": last_event.get("path", ""),
            "threat_score": round(final_score, 4),
            "action": threat.action,
            "timestamp": time.time(),
        }),
    )


async def _create_attack_session(
    fingerprint_hash: str,
    pattern_result: object,
    recent_events: list[dict],
    distinct_ips: int,
) -> None:
    """
    Create an AttackSession record in PostgreSQL
    and run AI analysis.
    """
    try:
        # Determine severity from confidence
        confidence = pattern_result.confidence
        if confidence > 0.9:
            severity = "high"
        elif confidence > 0.7:
            severity = "medium"
        else:
            severity = "low"

        # Call AI analyst
        ai_result = await analyze_attack(
            attack_type=pattern_result.pattern_type,
            fingerprint_data={
                "hash": fingerprint_hash,
                "distinct_ips": distinct_ips,
                "total_events": len(recent_events),
            },
            request_samples=recent_events[:20],
            detection_evidence=pattern_result.evidence,
        )

        # Create AttackSession in PostgreSQL
        async with async_session() as session:
            attack = AttackSession(
                org_id=DEFAULT_ORG_ID,
                fingerprint_hash=fingerprint_hash,
                attack_type=pattern_result.pattern_type,
                severity=severity,
                status="active",
                started_at=datetime.now(timezone.utc),
                total_requests=len(recent_events),
                total_fingerprints=1,
                total_ips=distinct_ips,
                ai_analysis=ai_result,
                ai_confidence=ai_result.get(
                    "confidence"
                ),
                ai_explanation=ai_result.get(
                    "explanation"
                ),
            )
            session.add(attack)
            await session.commit()

        logger.info(
            "Attack session created",
            extra={
                "fingerprint": fingerprint_hash,
                "type": pattern_result.pattern_type,
                "confidence": confidence,
            },
        )

    except Exception as e:
        logger.error(
            "Failed to create attack session",
            extra={
                "error": str(e),
                "fingerprint": fingerprint_hash,
            },
        )


async def _get_population_velocities(
    redis_client: aioredis.Redis,
) -> list[float]:
    """
    Get current RPM for all active fingerprints.

    Used by anomaly detection to compute z-scores.
    Scans all velocity:* keys and counts entries
    in the last 60 seconds.
    """
    now = time.time()
    velocities: list[float] = []

    cursor = 0
    while True:
        cursor, keys = await redis_client.scan(
            cursor=cursor,
            match="velocity:*",
            count=100,
        )
        if keys:
            pipe = redis_client.pipeline()
            for key in keys:
                pipe.zcount(key, now - 60, now)
            counts = await pipe.execute()
            velocities.extend(
                float(c) for c in counts
            )
        if cursor == 0:
            break

    return velocities


async def _batch_write_to_postgres(
    events: list[dict],
) -> None:
    """
    Batch write request logs to PostgreSQL.

    Uses the REAL fingerprint_hash from the event,
    not a random UUID.
    """
    try:
        async with async_session() as session:
            for event in events:
                req = RequestModel(
                    org_id=DEFAULT_ORG_ID,
                    fingerprint_hash=event.get(
                        "fingerprint", "unknown"
                    ),
                    ip_address=event.get(
                        "ip", "unknown"
                    ),
                    method=event.get("method", "GET"),
                    path=event.get("path", "/"),
                    status_code=(
                        int(event.get("status_code", 0))
                        or None
                    ),
                    threat_score=float(
                        event.get("threat_score", 0)
                    ),
                    action_taken=event.get(
                        "action", "allow"
                    ),
                    body_hash=(
                        event.get("body_hash") or None
                    ),
                )
                session.add(req)
            await session.commit()
    except Exception as e:
        logger.error(
            "PostgreSQL batch write failed",
            extra={
                "error": str(e),
                "event_count": len(events),
            },
        )


async def run_worker() -> None:
    """
    Main worker loop.

    Connects to Redis, creates consumer group,
    then loops forever processing events.
    """
    redis_client = aioredis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
    )

    await ensure_consumer_group(redis_client)
    logger.info(
        "Worker started",
        extra={"consumer": CONSUMER_NAME},
    )

    try:
        while True:
            try:
                await process_events(redis_client)
            except Exception as e:
                logger.error(
                    "Worker error",
                    extra={"error": str(e)},
                )
                await asyncio.sleep(1)
    finally:
        await redis_client.close()


if __name__ == "__main__":
    asyncio.run(run_worker())