"""
Circuit breaker for external dependencies (Redis, PostgreSQL).

PREVENTS cascading failures. When Redis is down, instead of
every request waiting 3 seconds for a timeout, the circuit
breaker skips Redis calls immediately and uses fallbacks.

THREE STATES:
  CLOSED: Everything working. All calls go through.
  OPEN: Service is down. Skip calls, use fallback. Fast.
  HALF_OPEN: Testing if service recovered. Try one call.

LIMITATIONS:
State is in-memory. If you run 3 API instances, each has
its own circuit breaker. One instance might think Redis is
up while another thinks it's down. In production, you'd
store state in... Redis (the thing that might be down).
This is a real distributed systems problem with no clean
answer. Acknowledged as a known limitation.
"""

import time
from enum import Enum


class CircuitState(Enum):
    CLOSED = "closed"      # Normal — everything works
    OPEN = "open"          # Broken — skip calls
    HALF_OPEN = "half_open"  # Testing — try one call


class CircuitBreaker:
    """
    Circuit breaker that tracks failures and prevents
    repeated calls to a failing service.
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
    ):
        """
        name: identifier for logging ("redis", "postgres")
        failure_threshold: how many failures before opening
        recovery_timeout: seconds to wait before testing again
        """
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout

        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.success_count_in_half_open = 0

    def can_execute(self) -> bool:
        """
        Should we attempt to call the service?

        CLOSED: yes, always
        OPEN: no, unless recovery_timeout has passed
               (then transition to HALF_OPEN)
        HALF_OPEN: yes (we're testing)
        """
        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            elapsed = time.time() - self.last_failure_time
            if elapsed > self.recovery_timeout:
                # Time to test — move to half-open
                self.state = CircuitState.HALF_OPEN
                self.success_count_in_half_open = 0
                return True
            return False  # Still waiting

        # HALF_OPEN — allow the test call
        return True

    def record_success(self) -> None:
        """
        The service call succeeded.

        CLOSED: reset failure count (good streak)
        HALF_OPEN: count successes, close after 3
        """
        if self.state == CircuitState.HALF_OPEN:
            self.success_count_in_half_open += 1
            if self.success_count_in_half_open >= 3:
                # Service is back! Close the circuit.
                self.state = CircuitState.CLOSED
                self.failure_count = 0
        elif self.state == CircuitState.CLOSED:
            self.failure_count = 0

    def record_failure(self) -> None:
        """
        The service call failed.

        Increment failure count. If threshold reached,
        open the circuit. If already HALF_OPEN, go
        back to OPEN (service still broken).
        """
        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.state == CircuitState.HALF_OPEN:
            # Test call failed — service still broken
            self.state = CircuitState.OPEN
        elif self.failure_count >= self.failure_threshold:
            # Too many failures — open the circuit
            self.state = CircuitState.OPEN

    def get_status(self) -> dict:
        """Current state for monitoring/debugging."""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
        }


# Pre-created breakers for our two external services
redis_breaker = CircuitBreaker(name="redis")
postgres_breaker = CircuitBreaker(name="postgres")