"""
Tests for the event logger.

Since event logging depends on Redis, we test:
1. The function signature and parameters
2. Error handling (Redis down → no crash)

Full integration tests (actually writing to Redis Stream)
will be in tests/integration/.
"""

import pytest
from unittest.mock import AsyncMock, patch

from Vigil.core.event_logger import log_request_event


class TestEventLoggerErrorHandling:
    """Event logger should never crash the request."""

    @pytest.mark.asyncio
    async def test_redis_failure_does_not_raise(self):
        """
        If Redis is down, log_request_event should
        catch the error and return normally.
        The request must not fail just because logging failed.
        """
        with patch(
            "Vigil.core.event_logger.get_redis"
        ) as mock_get_redis:
            mock_redis = AsyncMock()
            mock_redis.xadd.side_effect = ConnectionError(
                "Redis is down"
            )
            mock_get_redis.return_value = mock_redis

            # Should NOT raise an exception
            await log_request_event(
                fingerprint_hash="abc123def456789a",
                ip_address="1.2.3.4",
                method="GET",
                path="/api/users/1",
                status_code=200,
                threat_score=0.0,
                action_taken="allow",
            )

    @pytest.mark.asyncio
    async def test_successful_logging(self):
        """Verify correct data is passed to Redis XADD."""
        with patch(
            "Vigil.core.event_logger.get_redis"
        ) as mock_get_redis:
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis

            await log_request_event(
                fingerprint_hash="abc123def456789a",
                ip_address="1.2.3.4",
                method="POST",
                path="/api/auth/login",
                status_code=401,
                threat_score=0.75,
                action_taken="challenge",
                body_hash="deadbeef12345678",
            )

            # Verify xadd was called once
            mock_redis.xadd.assert_called_once()

            # Get the event dict that was passed
            call_args = mock_redis.xadd.call_args
            event = call_args[0][1]  # second positional arg

            assert event["fingerprint"] == "abc123def456789a"
            assert event["ip"] == "1.2.3.4"
            assert event["method"] == "POST"
            assert event["path"] == "/api/auth/login"
            assert event["status_code"] == "401"
            assert event["action"] == "challenge"
            assert event["body_hash"] == "deadbeef12345678"

    @pytest.mark.asyncio
    async def test_none_body_hash_becomes_empty_string(self):
        """body_hash=None should be stored as empty string."""
        with patch(
            "Vigil.core.event_logger.get_redis"
        ) as mock_get_redis:
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis

            await log_request_event(
                fingerprint_hash="abc123def456789a",
                ip_address="1.2.3.4",
                method="GET",
                path="/api/test",
                status_code=200,
                threat_score=0.0,
                action_taken="allow",
                body_hash=None,
            )

            call_args = mock_redis.xadd.call_args
            event = call_args[0][1]
            assert event["body_hash"] == ""

    @pytest.mark.asyncio
    async def test_none_status_code_becomes_zero(self):
        """status_code=None should be stored as "0"."""
        with patch(
            "Vigil.core.event_logger.get_redis"
        ) as mock_get_redis:
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis

            await log_request_event(
                fingerprint_hash="abc123def456789a",
                ip_address="1.2.3.4",
                method="GET",
                path="/api/test",
                status_code=None,
                threat_score=0.0,
                action_taken="allow",
            )

            call_args = mock_redis.xadd.call_args
            event = call_args[0][1]
            assert event["status_code"] == "0"