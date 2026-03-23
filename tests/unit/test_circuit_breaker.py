"""
Tests for circuit breaker state machine.

TESTING STRATEGY:
- State transitions: CLOSED → OPEN → HALF_OPEN → CLOSED
- Failure threshold: opens after exactly N failures
- Recovery: success resets failure count
- Half-open: 3 successes → close, 1 failure → reopen
- Timeout: transitions to half-open after waiting
"""

import time

from Vigil.core.circuit_breaker import (
    CircuitBreaker,
    CircuitState,
)


class TestCircuitBreakerStates:
    """Test state transitions."""

    def test_starts_closed(self):
        """Fresh circuit breaker should be closed (normal)."""
        cb = CircuitBreaker("test")
        assert cb.state == CircuitState.CLOSED
        assert cb.can_execute() is True

    def test_stays_closed_under_threshold(self):
        """2 failures with threshold 3 → still closed."""
        cb = CircuitBreaker("test", failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED
        assert cb.can_execute() is True

    def test_opens_at_threshold(self):
        """Exactly 3 failures with threshold 3 → opens."""
        cb = CircuitBreaker("test", failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.can_execute() is False

    def test_open_blocks_execution(self):
        """Open circuit should reject all calls."""
        cb = CircuitBreaker("test", failure_threshold=1)
        cb.record_failure()
        assert cb.can_execute() is False
        assert cb.can_execute() is False
        assert cb.can_execute() is False


class TestCircuitBreakerRecovery:
    """Test recovery from failures."""

    def test_success_resets_failure_count(self):
        """2 failures then a success → reset count."""
        cb = CircuitBreaker("test", failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()  # Resets to 0
        cb.record_failure()  # Count is now 1, not 3
        assert cb.state == CircuitState.CLOSED

    def test_transitions_to_half_open_after_timeout(self):
        """
        After recovery_timeout seconds, OPEN → HALF_OPEN.
        Uses very short timeout (0.1s) for fast testing.
        """
        cb = CircuitBreaker(
            "test",
            failure_threshold=1,
            recovery_timeout=0.1,
        )
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # Wait for recovery timeout
        time.sleep(0.15)

        # can_execute transitions to HALF_OPEN
        assert cb.can_execute() is True
        assert cb.state == CircuitState.HALF_OPEN

    def test_half_open_closes_after_3_successes(self):
        """HALF_OPEN + 3 successes → CLOSED."""
        cb = CircuitBreaker(
            "test",
            failure_threshold=1,
            recovery_timeout=0.01,
        )
        cb.record_failure()
        time.sleep(0.02)
        cb.can_execute()  # → HALF_OPEN

        cb.record_success()
        cb.record_success()
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_success()  # Third success
        assert cb.state == CircuitState.CLOSED

    def test_half_open_reopens_on_failure(self):
        """HALF_OPEN + 1 failure → back to OPEN."""
        cb = CircuitBreaker(
            "test",
            failure_threshold=1,
            recovery_timeout=0.01,
        )
        cb.record_failure()
        time.sleep(0.02)
        cb.can_execute()  # → HALF_OPEN

        cb.record_failure()  # Test call failed
        assert cb.state == CircuitState.OPEN


class TestCircuitBreakerStatus:
    """Test monitoring output."""

    def test_status_contains_all_fields(self):
        cb = CircuitBreaker("redis")
        status = cb.get_status()
        assert status["name"] == "redis"
        assert status["state"] == "closed"
        assert status["failure_count"] == 0

    def test_status_reflects_current_state(self):
        cb = CircuitBreaker("test", failure_threshold=1)
        cb.record_failure()
        status = cb.get_status()
        assert status["state"] == "open"
        assert status["failure_count"] == 1