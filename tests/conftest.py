"""
Shared test fixtures.

Two types of test clients:

1. client — works WITHOUT Redis/PostgreSQL.
   For unit tests. Rate limiter catches errors silently.

2. live_client — REQUIRES Redis/PostgreSQL running.
   For integration tests. Manually initializes all
   connections before tests and cleans up after.

WHY MANUAL INIT:
httpx's ASGITransport does NOT trigger FastAPI's
lifespan events (init_db, init_redis, etc.).
When you run the real server with uvicorn, lifespan
runs automatically. But in tests, we're sending
requests directly to the app object without a real
server, so we must initialize services ourselves.
"""

import pytest
from httpx import AsyncClient, ASGITransport

from Vigil.main import app


@pytest.fixture
async def client():
    """
    Unit test client — works without external services.
    Use for tests that don't need Redis or PostgreSQL.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://test"
    ) as c:
        yield c


@pytest.fixture
async def live_client():
    """
    Integration test client — requires Redis and PostgreSQL.

    Manually runs the same initialization that FastAPI's
    lifespan would run (init_db, init_redis, etc.)
    because httpx ASGITransport skips lifespan events.
    """
    from Vigil.db.engine import init_db, close_db
    from Vigil.cache.client import init_redis, close_redis
    from Vigil.core.cold_start import cold_start
    from Vigil.core.setup import ensure_default_organization

    # ── Same as lifespan startup ──
    await init_db()
    await init_redis()
    await cold_start.initialize()
    await ensure_default_organization()

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://test"
    ) as c:
        yield c

    # ── Same as lifespan shutdown ──
    await close_db()
    await close_redis()