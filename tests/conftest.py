"""
Shared test fixtures.

The health check test works WITHOUT Redis/PostgreSQL
because the rate limiter gracefully catches connection
errors and lets requests through.
"""

import pytest
from httpx import AsyncClient, ASGITransport

from Vigil.main import app


@pytest.fixture
async def client():
    """
    Test client that sends requests directly to the
    ASGI app without starting a real server.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://test"
    ) as c:
        yield c