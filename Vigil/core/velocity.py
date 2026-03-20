"""
Sliding window velocity tracking using Redis sorted sets.

WHAT THIS TRACKS:
- Requests per minute (RPM) in the last 1 minute
- Average RPM over the last 5 minutes
- Requests per hour (RPH) in the last 1 hour

WHY THREE WINDOWS:
- 1-minute: catches sudden bursts (DDoS, brute force)
- 5-minute average: smooths out natural variation
- 1-hour: catches slow-but-persistent attacks

MEMORY USAGE:
Each request = ~50 bytes in Redis.
100 RPM × 60 minutes = 6000 entries × 50 bytes = ~300KB per fingerprint.
1000 active fingerprints = ~300MB. Well within Redis capacity.

CLEANUP:
We remove entries older than 1 hour on every check.
This prevents the sorted set from growing forever.
The TTL of 2 hours is a safety net — if a fingerprint
stops sending requests, the entire key is deleted after 2h.
"""

import time
import uuid

from Vigil.cache.client import get_redis


class VelocityTracker:
    """Track request velocity per fingerprint using Redis sorted sets."""

    async def record_and_check(
        self,
        fingerprint_hash: str,
    ) -> dict:
        """
        Record a new request and return current velocities.

        WHAT HAPPENS:
        1. Add current timestamp to the sorted set
        2. Remove timestamps older than 1 hour (cleanup)
        3. Count timestamps in last 1 minute
        4. Count timestamps in last 5 minutes
        5. Count timestamps in last 1 hour
        6. Set key to expire after 2 hours (safety net)

        All 6 operations are batched in ONE Redis pipeline
        (one network round-trip instead of six).

        RETURNS:
        {
            "rpm_1": 45,        # requests in last 1 minute
            "rpm_5": 38.2,      # average RPM over last 5 minutes
            "rph": 2100,        # requests in last 1 hour
        }
        """
        redis = get_redis()
        now = time.time()
        key = f"velocity:{fingerprint_hash}"

        # Each entry needs a unique member name.
        # timestamp + random suffix ensures uniqueness even
        # if two requests arrive at the exact same microsecond.
        member = f"{now}:{uuid.uuid4().hex[:8]}"

        # Pipeline: batch all commands into one round-trip
        pipe = redis.pipeline(transaction=False)

        # 1. Add this request's timestamp (score = timestamp)
        pipe.zadd(key, {member: now})

        # 2. Remove entries older than 1 hour
        pipe.zremrangebyscore(key, 0, now - 3600)

        # 3. Count requests in last 1 minute
        pipe.zcount(key, now - 60, now)

        # 4. Count requests in last 5 minutes
        pipe.zcount(key, now - 300, now)

        # 5. Count requests in last 1 hour
        pipe.zcount(key, now - 3600, now)

        # 6. Set key TTL to 2 hours (auto-delete if inactive)
        pipe.expire(key, 7200)

        # Execute all 6 commands in one network call
        results = await pipe.execute()

        # results[0] = ZADD result (number of new elements added)
        # results[1] = ZREMRANGEBYSCORE result (number removed)
        # results[2] = ZCOUNT for 1 minute
        # results[3] = ZCOUNT for 5 minutes
        # results[4] = ZCOUNT for 1 hour
        # results[5] = EXPIRE result (True/False)

        count_1m = results[2]
        count_5m = results[3]
        count_1h = results[4]

        return {
            "rpm_1": count_1m,
            "rpm_5": round(count_5m / 5, 2) if count_5m else 0,
            "rph": count_1h,
        }


# Singleton — import this in other files
velocity_tracker = VelocityTracker()