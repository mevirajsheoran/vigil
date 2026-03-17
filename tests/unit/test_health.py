"""
First test — verifies the server starts and
health check responds correctly.

Works without Redis/PostgreSQL because the rate
limiter catches RuntimeError and lets requests through.
"""

import pytest


@pytest.mark.asyncio
async def test_health_returns_200(client):
    response = await client.get("/health")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_health_returns_correct_body(client):
    response = await client.get("/health")
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "Vigil"