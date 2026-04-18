"""
Rate limiting on Vigil's own API.

THE IRONY: An API abuse detection tool that can itself
be abused. Without this middleware, someone could send
1 million requests to /v1/analyze per second, crashing
Vigil before it can protect anything.

HOW IT WORKS:
- For each IP address, keep a counter in Redis
- Counter auto-expires after 60 seconds
- If counter exceeds 1000 → reject with 429 Too Many Requests
- If Redis is down → let requests through (fail-open)

WHY FAIL-OPEN:
If Redis dies and we block ALL requests, the entire
system is down. Better to let requests through without
rate limiting than to block everything. The actual
detection still has other safeguards.
"""

from fastapi import Request, HTTPException

from Vigil.cache.client import get_redis
from Vigil.config import logger


async def rate_limit_vigil(request: Request) -> None:
    """Rate limit Vigil's own API endpoints."""
    try:
        r = get_redis()
        # Get the IP of whoever is calling Vigil
        client_ip = (
            request.client.host
            if request.client
            else "unknown"
        )
        key = f"vigil_ratelimit:{client_ip}"

        # INCR atomically increments and returns new value.
        # If key doesn't exist, Redis creates it with value 1.
        count = await r.incr(key)

        # Set expiry only on FIRST request (count == 1)
        # so the window doesn't keep resetting
        if count == 1:
            await r.expire(key, 60)  # expires in 60 seconds


         # Raised to 10000 for load testing.
        # In production with real clients coming from
        # different IPs, the per-IP limit of 1000 is fine.
        # But Locust sends ALL requests from 127.0.0.1,
        # so they all share one counter.
        if count > 10000:
            raise HTTPException(
                status_code=429,
                detail="Vigil API rate limit exceeded",
            )
    except HTTPException:
        # Re-raise HTTP exceptions (don't catch our own 429)
        raise
    except Exception as e:
        # Redis is down or unreachable — fail OPEN
        # (let requests through rather than blocking everything)
        logger.warning(
            "Rate limit check failed",
            extra={"error": str(e)},
        )