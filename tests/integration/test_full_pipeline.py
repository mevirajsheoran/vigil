"""
THE MOST IMPORTANT TEST IN THE PROJECT.

Tests the entire system end-to-end:
  1. Send enumeration requests → logged to Redis Stream
  2. Worker processes events → detects pattern → updates score
  3. Next request → reads cached score → BLOCKED

REQUIRES:
  - Redis running on the configured port
  - PostgreSQL running on the configured port
  - Tables created (alembic upgrade head)

Run with:
  pytest tests/integration/ -v
"""

import pytest
import asyncio

import redis.asyncio as aioredis
from Vigil.config import settings
from Vigil.workers.stream_consumer import (
    process_events,
    ensure_consumer_group,
)


def _can_connect() -> bool:
    """
    Check if Redis is reachable.
    If not, integration tests are skipped automatically.
    """
    async def _check():
        try:
            r = aioredis.from_url(
                settings.redis_url,
                decode_responses=True,
            )
            await r.ping()
            await r.aclose()
            return True
        except Exception:
            return False

    try:
        return asyncio.run(_check())
    except Exception:
        return False


requires_services = pytest.mark.skipif(
    not _can_connect(),
    reason=(
        "Redis and PostgreSQL required "
        "for integration tests"
    ),
)


@requires_services
@pytest.mark.asyncio
async def test_enumeration_detected_and_blocked(
    live_client,
):
    """
    FULL PIPELINE TEST:

    1. Send 25 sequential requests (/api/users/1 to /25)
    2. All should be ALLOWED (no history yet)
    3. Run worker to process events
    4. Worker detects enumeration pattern
    5. Worker updates threat score in Redis
    6. Send request #26
    7. Should be BLOCKED or CHALLENGED
    """
    # ── Step 1: Send enumeration requests ──
    for i in range(1, 26):
        response = await live_client.post(
            "/v1/analyze",
            json={
                "method": "GET",
                "path": f"/api/users/{i}",
            },
            headers={
                "User-Agent": "python-requests/2.31",
                "Accept-Language": "",
                "Accept-Encoding": "gzip, deflate",
            },
        )
        assert response.status_code == 200

    # ── Step 2: Trigger worker processing ──
    redis_client = aioredis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
    )
    await ensure_consumer_group(redis_client)

    # Process events multiple times to ensure
    # history accumulates and detection runs
    for _ in range(3):
        await process_events(redis_client)
        await asyncio.sleep(0.1)

    # ── Step 3: Next request should be blocked ──
    response = await live_client.post(
        "/v1/analyze",
        json={
            "method": "GET",
            "path": "/api/users/26",
        },
        headers={
            "User-Agent": "python-requests/2.31",
            "Accept-Language": "",
            "Accept-Encoding": "gzip, deflate",
        },
    )
    data = response.json()

    assert data["action"] in ("block", "challenge"), (
        f"Expected block/challenge but got "
        f"'{data['action']}' "
        f"with score {data['threat_score']}"
    )
    assert data["threat_score"] > 0.5

    # Cleanup
    await redis_client.aclose()


@requires_services
@pytest.mark.asyncio
async def test_normal_traffic_stays_allowed(
    live_client,
):
    """
    Normal browsing should NEVER be blocked.

    Different paths, no sequential pattern,
    no login hammering — just regular browsing.
    """
    normal_paths = [
        "/api/products",
        "/api/cart",
        "/about",
        "/api/products/shoes",
        "/api/profile",
        "/api/settings",
        "/api/notifications",
    ]
    for path in normal_paths:
        response = await live_client.post(
            "/v1/analyze",
            json={"method": "GET", "path": path},
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0)"
                ),
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
            },
        )
        data = response.json()
        assert data["action"] == "allow", (
            f"Normal request to {path} "
            f"got '{data['action']}'"
        )