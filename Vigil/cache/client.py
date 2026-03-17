"""
Redis client setup.

One shared client used everywhere in the app:
- Fast path checks (is this fingerprint blocked?)
- Velocity tracking (how many requests per minute?)
- Threat score cache (what's this fingerprint's score?)
- Event streaming (async logging to background workers)
- Pub/sub (pushing live events to dashboard)

WHY ONE SHARED CLIENT:
Each Redis client maintains a connection pool.
Multiple clients = multiple pools = wasted connections.
One client, imported everywhere = efficient.
"""

import redis.asyncio as redis

from Vigil.config import settings, logger


# Global variable — starts as None, set during startup
redis_client: redis.Redis | None = None


async def init_redis() -> None:
    """
    Connect to Redis on startup.

    from_url() creates a connection pool automatically.
    ping() verifies Redis is reachable.
    """
    global redis_client
    redis_client = redis.from_url(
        settings.redis_url,
        encoding="utf-8",
        # decode_responses=True means Redis returns
        # Python strings instead of raw bytes.
        # Without it: b"hello" (bytes)
        # With it: "hello" (string)
        decode_responses=True,
    )
    await redis_client.ping()
    logger.info("Redis connected")


async def close_redis() -> None:
    """Close Redis connection on shutdown."""
    global redis_client
    if redis_client:
        await redis_client.close()
        logger.info("Redis connection closed")


def get_redis() -> redis.Redis:
    """
    Get the Redis client.

    Any file that needs Redis calls this function.
    If Redis hasn't been initialized yet (app hasn't
    started), it raises a clear error instead of
    returning None and causing confusing NoneType errors.
    """
    if redis_client is None:
        raise RuntimeError(
            "Redis not initialized. Call init_redis() first."
        )
    return redis_client