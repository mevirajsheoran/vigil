"""
Fast path check — runs on EVERY request.

THIS IS THE MOST PERFORMANCE-CRITICAL CODE IN VIGIL.

Target: < 3ms total per request.

WHAT IT CHECKS (all from Redis — sub-millisecond):
1. Compute fingerprint from HTTP headers
2. Extract real IP from proxy headers
3. Is this fingerprint blocklisted?
4. Is this fingerprint allowlisted?
5. How fast is this fingerprint going? (velocity)
6. What's the cached threat score? (from background worker)
7. Decision: allow / challenge / block

WHAT IT DOES NOT CHECK (too slow for per-request):
- Pattern detection (needs 10+ requests of history)
- Anomaly detection (needs population statistics)
- AI analysis (needs seconds)

Those are done by the background worker, which updates
the cached threat score in Redis. The fast path reads
that cached score.

DETECTION LATENCY:
There's a 2-5 second delay between a new attack starting
and the first block. During this window, malicious requests
pass through. This is because:
1. Events are queued in Redis Stream
2. Worker processes every 3 seconds
3. Worker updates the cached score
4. NEXT request reads the updated score → blocked

This is the same tradeoff every async detection system
makes, including Cloudflare's bot management.
"""

from dataclasses import dataclass

from fastapi import Request

from Vigil.core.fingerprinting import compute_fingerprint
from Vigil.core.ip_extraction import extract_real_ip
from Vigil.core.velocity import velocity_tracker
from Vigil.core.cold_start import cold_start
from Vigil.cache.client import get_redis


@dataclass
class FastPathResult:
    """Result of the fast path check."""
    fingerprint_hash: str
    ip_address: str
    action: str         # "allow", "block", or "challenge"
    reason: str         # why this action was taken
    threat_score: float
    velocity_rpm: int
    phase: str          # cold start phase


async def fast_path_check(
    request: Request,
) -> FastPathResult:
    """
    Run all fast-path checks and return a decision.

    ORDER MATTERS — we check cheapest/most-decisive first:
    1. Blocklist (instant rejection for known bad actors)
    2. Allowlist (instant pass for trusted clients)
    3. Velocity (catch high-speed attacks immediately)
    4. Cached score (use background worker's analysis)
    """
    redis = get_redis()
    thresholds = cold_start.get_thresholds()

    # Step 1: WHO is this?
    fp = compute_fingerprint(request)

    # Step 2: WHERE are they?
    ip = extract_real_ip(request)

    # Step 3: Are they already blocked?
    is_blocked = await redis.get(
        f"blocked:{fp.fingerprint_hash}"
    )
    if is_blocked:
        return FastPathResult(
            fingerprint_hash=fp.fingerprint_hash,
            ip_address=ip,
            action="block",
            reason=f"blocklisted: {is_blocked}",
            threat_score=1.0,
            velocity_rpm=0,
            phase=thresholds.phase,
        )

    # Step 4: Are they pre-approved?
    is_allowed = await redis.get(
        f"allowed:{fp.fingerprint_hash}"
    )
    if is_allowed:
        return FastPathResult(
            fingerprint_hash=fp.fingerprint_hash,
            ip_address=ip,
            action="allow",
            reason="allowlisted",
            threat_score=0.0,
            velocity_rpm=0,
            phase=thresholds.phase,
        )

    # Step 5: How fast are they going?
    velocity = await velocity_tracker.record_and_check(
        fp.fingerprint_hash
    )

    # Velocity hard limit — instant block
    if velocity["rpm_1"] > thresholds.velocity_hard_limit:
        # Block for 1 hour and record why
        await redis.setex(
            f"blocked:{fp.fingerprint_hash}",
            3600,
            "velocity_limit_exceeded",
        )
        return FastPathResult(
            fingerprint_hash=fp.fingerprint_hash,
            ip_address=ip,
            action="block",
            reason=(
                f"velocity {velocity['rpm_1']} RPM "
                f"exceeds limit "
                f"{thresholds.velocity_hard_limit}"
            ),
            threat_score=1.0,
            velocity_rpm=velocity["rpm_1"],
            phase=thresholds.phase,
        )

    # Step 6: What does the background worker think?
    cached_score = await redis.get(
        f"threat:{fp.fingerprint_hash}"
    )
    threat_score = (
        float(cached_score) if cached_score else 0.0
    )

    # Compare against thresholds
    if threat_score >= thresholds.block_score_threshold:
        action = "block"
        reason = (
            f"threat_score {threat_score:.2f} "
            f">= block threshold "
            f"{thresholds.block_score_threshold}"
        )
    elif (
        threat_score
        >= thresholds.challenge_score_threshold
    ):
        action = "challenge"
        reason = (
            f"threat_score {threat_score:.2f} "
            f">= challenge threshold "
            f"{thresholds.challenge_score_threshold}"
        )
    else:
        action = "allow"
        reason = "below thresholds"

    return FastPathResult(
        fingerprint_hash=fp.fingerprint_hash,
        ip_address=ip,
        action=action,
        reason=reason,
        threat_score=threat_score,
        velocity_rpm=velocity["rpm_1"],
        phase=thresholds.phase,
    )