"""
Threat score composition — combines ALL detection signals
into ONE number between 0.0 and 1.0.

THIS IS THE DECISION MAKER.

Score >= 0.85 → BLOCK
Score >= 0.65 → CHALLENGE (rate limit + retry-after)
Score <  0.65 → ALLOW

SIX SIGNALS, EACH NORMALIZED TO 0.0-1.0:
1. Velocity (0.20 weight)    → how fast is this fingerprint
2. Pattern (0.30 weight)     → enumeration/stuffing confidence
3. Anomaly (0.20 weight)     → z-score statistical outlier
4. Regularity (0.10 weight)  → bot-like timing consistency
5. IP diversity (0.10 weight)→ number of different IPs used
6. History (0.10 weight)     → past blocking count
"""

import math
import time
from dataclasses import dataclass


@dataclass
class ThreatSignals:
    """
    Raw signal values from all detection systems.
    Each system computes its own value; this struct
    collects them all for scoring.
    """
    velocity_rpm: float = 0.0
    velocity_hard_limit: float = 200.0
    pattern_confidence: float = 0.0
    zscore: float = 0.0
    regularity_score: float = 0.0
    distinct_ip_count: int = 1
    historical_blocks: int = 0


@dataclass
class ThreatScore:
    """
    Final scoring result.

    score: 0.0 to 1.0
    components: individual normalized signal values
    action: "allow", "challenge", or "block"
    explanation: human-readable summary
    """
    score: float
    components: dict[str, float]
    action: str
    explanation: str


def _normalize_velocity(
    rpm: float,
    hard_limit: float,
) -> float:
    """
    Normalize RPM to 0.0-1.0 range.

    0 RPM → 0.0
    At the hard limit → 1.0
    Above the limit → still 1.0 (capped)

    Example with limit = 200:
      50 RPM → 0.25
      100 RPM → 0.50
      200 RPM → 1.00
      500 RPM → 1.00 (capped)
    """
    if hard_limit <= 0:
        return 0.0
    return min(1.0, rpm / hard_limit)


def _normalize_zscore(zscore: float) -> float:
    """
    Normalize Z-score to 0.0-1.0 using a sigmoid function.

    The sigmoid is shifted so that Z=2 maps to ~0.5:
      Z=0 → 0.12 (low — average speed)
      Z=1 → 0.27 (slightly elevated)
      Z=2 → 0.50 (moderately elevated)
      Z=3 → 0.73 (significantly elevated)
      Z=5 → 0.95 (extreme outlier)

    WHY SIGMOID (not linear):
    Linear: Z=100 would give score=50 → nonsensical
    Sigmoid: Z=100 gives 1.0 → capped naturally
    The S-curve also means small Z changes near 0
    have little effect, while changes near 2-3
    have the most impact.
    """
    return 1.0 / (1.0 + math.exp(-(zscore - 2)))


def _normalize_ip_count(count: int) -> float:
    """
    Normalize IP count to 0.0-1.0 using logarithm.

    1 IP → 0.0 (normal — one device, one IP)
    5 IPs → 0.39 (slightly suspicious)
    10 IPs → 0.55 (moderately suspicious)
    50 IPs → 0.80 (very suspicious — proxy network)

    WHY LOG (not linear):
    Linear: the difference between 1 and 5 IPs is the
    same as 95 and 100. But 1→5 is WAY more suspicious
    than 95→100. Log captures this — early IPs matter more.
    """
    if count <= 1:
        return 0.0
    return min(1.0, math.log2(count) / 6.0)


def compute_threat_score(
    signals: ThreatSignals,
    weights: dict[str, float] | None = None,
    block_threshold: float = 0.85,
    challenge_threshold: float = 0.65,
) -> ThreatScore:
    """
    Compute the final threat score from all signals.

    STEPS:
    1. Normalize each signal to 0.0-1.0
    2. Multiply each by its weight
    3. Sum all weighted values → raw score
    4. Apply pattern confidence override (if applicable)
    5. Determine action based on thresholds
    6. Generate human-readable explanation
    """
    # Default weights (explained in module docstring)
    w = weights or {
        "velocity": 0.20,
        "pattern": 0.30,
        "anomaly": 0.20,
        "regularity": 0.10,
        "ip_diversity": 0.10,
        "history": 0.10,
    }

    # Step 1: Normalize each signal to 0.0-1.0
    velocity_normalized = _normalize_velocity(
        signals.velocity_rpm, signals.velocity_hard_limit
    )
    pattern_normalized = signals.pattern_confidence
    # Pattern confidence is already 0-1
    anomaly_normalized = _normalize_zscore(signals.zscore)
    regularity_normalized = signals.regularity_score
    # Regularity is already 0-1
    ip_normalized = _normalize_ip_count(
        signals.distinct_ip_count
    )
    history_normalized = min(
        1.0, signals.historical_blocks / 5.0
    )
    # 5+ past blocks → maxed out

    components = {
        "velocity": round(velocity_normalized, 4),
        "pattern": round(pattern_normalized, 4),
        "anomaly": round(anomaly_normalized, 4),
        "regularity": round(regularity_normalized, 4),
        "ip_diversity": round(ip_normalized, 4),
        "history": round(history_normalized, 4),
    }

    # Step 2-3: Weighted sum
    raw_score = sum(
        w[key] * components[key] for key in w
    )
    final_score = round(
        min(1.0, max(0.0, raw_score)), 4
    )

    # Step 4: PATTERN CONFIDENCE OVERRIDE
    # High-confidence pattern match should guarantee
    # blocking regardless of other weak signals.
    # Without this, a slow careful attacker could score
    # below threshold because weak velocity/anomaly
    # dilute the strong pattern signal.
    if signals.pattern_confidence > 0.95:
        final_score = max(final_score, 0.85)
    elif signals.pattern_confidence > 0.85:
        final_score = max(final_score, 0.70)

    # Step 5: Determine action
    if final_score >= block_threshold:
        action = "block"
    elif final_score >= challenge_threshold:
        action = "challenge"
    else:
        action = "allow"

    # Step 6: Explanation — show top 3 signals
    top_signals = sorted(
        components.items(),
        key=lambda x: x[1],
        reverse=True,
    )[:3]

    explanation = (
        f"Score {final_score:.2f} (action: {action}). "
        f"Top signals: "
        + ", ".join(
            f"{name}={val:.2f}"
            for name, val in top_signals
        )
    )

    return ThreatScore(
        score=final_score,
        components=components,
        action=action,
        explanation=explanation,
    )


def apply_time_decay(
    raw_score: float,
    last_suspicious_at: float,
    half_life_seconds: float = 3600.0,
) -> float:
    """
    Exponential time decay — threat score decreases over time.

    FORMULA:
    decayed = raw_score × e^(-0.693 × age / half_life)

    With half_life = 1 hour (3600 seconds):
      Just now:      0.80 × 1.0 = 0.80
      30 min later:  0.80 × 0.71 = 0.57
      1 hour later:  0.80 × 0.50 = 0.40 (halved!)
      2 hours later: 0.80 × 0.25 = 0.20
      6 hours later: 0.80 × 0.016 = 0.013 (basically zero)

    WHY EXPONENTIAL (not linear):
    Linear: score drops to 0 at exactly half_life → abrupt
    Exponential: score gradually fades → smooth recovery
    Also, recent activity matters much more than old activity.

    WHY 0.693:
    ln(2) = 0.693. This makes the formula produce exactly
    half the value at t = half_life. It's the mathematical
    definition of half-life.
    """
    age_seconds = time.time() - last_suspicious_at
    if age_seconds <= 0:
        return raw_score

    decay_factor = math.exp(
        -0.693 * age_seconds / half_life_seconds
    )
    return raw_score * decay_factor