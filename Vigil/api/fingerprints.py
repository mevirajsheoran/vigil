"""
Fingerprint management endpoints.

LIST: See all detected fingerprints with their scores
BLOCK: Manually block a fingerprint (ban for N hours)
ALLOW: Manually allowlist a fingerprint (never block)
UNBLOCK: Remove a block

These are used by the dashboard for manual intervention.
When Vigil's automated detection makes a mistake
(false positive), admins can fix it here.
"""

from fastapi import APIRouter

from Vigil.cache.client import get_redis

router = APIRouter(
    prefix="/v1/fingerprints",
    tags=["Fingerprints"],
)


@router.get("")
async def list_fingerprints(
    limit: int = 20,
    blocked_only: bool = False,
):
    """
    List fingerprints sorted by threat score (highest first).

    Uses the vigil:active_fingerprints sorted set that the
    background worker maintains. This is O(log N) — instant
    even with 100K fingerprints.

    If blocked_only=True, only return blocked fingerprints.
    """
    redis = get_redis()
    fingerprints = []

    # Read from sorted set (highest scores first)
    # zrevrangebyscore: reverse range by score
    # "+inf" to "-inf" = all scores, highest first
    results = await redis.zrevrangebyscore(
        "vigil:active_fingerprints",
        "+inf",
        "-inf",
        start=0,
        num=limit * 2,  # fetch extra, filter below
        withscores=True,
    )

    for fp_hash, score in results:
        is_blocked = bool(
            await redis.get(f"blocked:{fp_hash}")
        )
        is_allowed = bool(
            await redis.get(f"allowed:{fp_hash}")
        )

        if blocked_only and not is_blocked:
            continue

        fingerprints.append({
            "fingerprint": fp_hash,
            "threat_score": round(score, 4),
            "is_blocked": is_blocked,
            "is_allowlisted": is_allowed,
        })

        if len(fingerprints) >= limit:
            break

    return fingerprints


@router.post("/{fingerprint_hash}/block")
async def block_fingerprint(
    fingerprint_hash: str,
    reason: str = "manual_block",
    duration_hours: int = 24,
):
    """
    Manually block a fingerprint.

    Sets a Redis key that the fast path checks on every
    request. Blocked fingerprints get instant 403 responses
    without any further analysis.

    duration_hours: how long to block (default 24 hours).
    After this time, Redis auto-deletes the key and the
    fingerprint can access the API again.
    """
    redis = get_redis()
    await redis.setex(
        f"blocked:{fingerprint_hash}",
        duration_hours * 3600,
        reason,
    )
    # Remove from allowlist if present
    await redis.delete(f"allowed:{fingerprint_hash}")

    return {
        "status": "blocked",
        "fingerprint": fingerprint_hash,
        "duration_hours": duration_hours,
        "reason": reason,
    }


@router.post("/{fingerprint_hash}/allow")
async def allowlist_fingerprint(
    fingerprint_hash: str,
):
    """
    Manually allowlist a fingerprint.

    Allowlisted fingerprints always get instant "allow"
    responses. Use this for known-good API clients,
    monitoring tools, or after confirming a false positive.

    No expiry — stays allowlisted until manually removed.
    """
    redis = get_redis()
    await redis.set(
        f"allowed:{fingerprint_hash}", "manual"
    )
    # Remove block if present
    await redis.delete(f"blocked:{fingerprint_hash}")

    return {
        "status": "allowlisted",
        "fingerprint": fingerprint_hash,
    }


@router.delete("/{fingerprint_hash}/block")
async def unblock_fingerprint(
    fingerprint_hash: str,
):
    """Remove a block from a fingerprint."""
    redis = get_redis()
    await redis.delete(f"blocked:{fingerprint_hash}")

    return {
        "status": "unblocked",
        "fingerprint": fingerprint_hash,
    }