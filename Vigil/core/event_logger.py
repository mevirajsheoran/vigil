"""
Async event logging to Redis Streams.

FLOW:
1. Request hits Vigil
2. Fast path makes a decision (allow/block/challenge)
3. Event is pushed to Redis Stream (< 0.5ms)
4. Response is sent to user
5. Background worker reads from stream (every 3 seconds)
6. Worker batch-writes events to PostgreSQL

MAXLEN:
We cap the stream at 100,000 events. At 100 RPS,
that's ~17 minutes of buffer. If the worker falls
behind for longer than that, oldest events are dropped.
In practice, the worker processes events every 3 seconds,
so the stream rarely has more than a few hundred events.

NON-BLOCKING:
If Redis is slow or down, we skip logging rather than
slowing down the response. The request still gets processed;
we just lose the log entry. This is an acceptable tradeoff
because logging is less critical than the actual
allow/block decision.
"""

import time

from Vigil.cache.client import get_redis
from Vigil.config import logger


# Key name for the Redis Stream
# All request events go into this one stream
STREAM_KEY = "vigil:request_events"


async def log_request_event(
    fingerprint_hash: str,
    ip_address: str,
    method: str,
    path: str,
    status_code: int | None,
    threat_score: float,
    action_taken: str,
    body_hash: str | None = None,
) -> None:
    """
    Push a request event to Redis Stream.

    PARAMETERS:
    - fingerprint_hash: 16-char device fingerprint
    - ip_address: real client IP
    - method: HTTP method (GET, POST, etc.)
    - path: request path (/api/users/5)
    - status_code: HTTP status from the protected API
    - threat_score: Vigil's threat score for this request
    - action_taken: what Vigil decided (allow/block/challenge)
    - body_hash: hash of request body (for credential stuffing)

    Redis XADD stores all values as strings, so we
    convert everything to str before sending.
    """
    redis = get_redis()

    try:
        event = {
            "fingerprint": fingerprint_hash,
            "ip": ip_address,
            "method": method,
            "path": path,
            "status_code": str(status_code or 0),
            "threat_score": str(threat_score),
            "action": action_taken,
            "body_hash": body_hash or "",
            "timestamp": str(time.time()),
        }

        # XADD: add event to stream
        # maxlen=100000: cap at 100K events (auto-delete oldest)
        # The "~" in maxlen means "approximately" — Redis may
        # keep slightly more than 100K for efficiency
        await redis.xadd(STREAM_KEY, event, maxlen=100000)

    except Exception as e:
        # If Redis is down, log a warning but DON'T crash.
        # The request still gets processed — we just lose
        # this particular log entry.
        logger.warning(
            "Failed to log request event",
            extra={
                "error": str(e),
                "fingerprint": fingerprint_hash,
            },
        )
        