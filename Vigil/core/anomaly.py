"""
Statistical anomaly detection.

Two methods that work together:

1. Z-SCORE: "Is this fingerprint's request rate
   abnormal compared to everyone else?"
   Uses trimmed statistics to resist attacker pollution.

2. INTERVAL REGULARITY: "Are requests arriving at
   suspiciously consistent intervals?"
   Humans are messy. Bots are precise.

COMBINED DECISION:
- High Z-score + high regularity = almost certainly a bot
- High Z-score + low regularity = might be a busy legitimate user
- Low Z-score + high regularity = might be a cron job / health check
- Low Z-score + low regularity = normal human
"""

import math
from dataclasses import dataclass


@dataclass
class AnomalyResult:
    """
    Result of anomaly detection.

    zscore: how many std devs away from population average
    regularity_score: 0.0 (human-like) to 1.0 (bot-like)
    is_anomalous: final yes/no decision
    evidence: human-readable explanations
    """
    zscore: float
    regularity_score: float
    is_anomalous: bool
    evidence: list[str]


def compute_zscore(
    value: float,
    population_values: list[float],
    trim_pct: float = 0.05,
) -> float:
    """
    Compute Z-score using TRIMMED mean and std dev.

    WHAT IS TRIMMING:
    Remove the top 5% and bottom 5% of values before
    calculating the average and standard deviation.

    WHY TRIM:
    Without trimming, attackers shift the average:
      Normal: [3, 4, 5, 4, 3] → mean = 3.8
      With attackers: [3, 4, 5, 4, 3, 200, 200, 200] → mean = 52
      New attacker at 200: Z = (200-52)/85 = 1.7 → NOT flagged!

    With trimming (remove 200s):
      Trimmed mean = 3.8
      New attacker at 200: Z = (200-3.8)/0.8 = 245 → FLAGGED!

    WHY 20 MINIMUM:
    With fewer than 20 data points, trimming removes
    too large a proportion. 5% of 10 = 0.5, which rounds
    to 0 or 1 — not meaningful. With 20+, 5% = 1 value
    from each end, which is a reasonable trim.

    RETURNS:
    0.0 if not enough data (can't compute meaningful Z-score)
    Otherwise, the Z-score (can be negative if below average)
    """
    n = len(population_values)
    if n < 20:
        return 0.0

    sorted_vals = sorted(population_values)
    trim_count = int(n * trim_pct)

    # Remove top and bottom trim_pct
    if trim_count == 0:
        trimmed = sorted_vals
    else:
        trimmed = sorted_vals[trim_count: n - trim_count]

    if not trimmed:
        return 0.0

    # Calculate mean (average)
    mean = sum(trimmed) / len(trimmed)

    # Calculate variance (average squared distance from mean)
    variance = sum(
        (v - mean) ** 2 for v in trimmed
    ) / len(trimmed)

    # Standard deviation = square root of variance
    std = math.sqrt(variance)

    # If everyone has the same value, std = 0, can't divide
    if std == 0:
        return 0.0

    # Z-score = how many std devs away from mean
    return (value - mean) / std


def compute_interval_regularity(
    timestamps: list[float],
) -> float:
    """
    Measure how regular the time intervals between
    requests are.

    RETURNS:
    0.0 = completely irregular (human-like)
    1.0 = perfectly regular (bot-like)

    HOW IT WORKS:
    1. Sort timestamps
    2. Compute intervals between consecutive timestamps
    3. Calculate CV (coefficient of variation) of intervals
    4. Transform CV into a 0-1 regularity score:
       regularity = 1.0 - (CV / 2.0), clamped to [0, 1]

    EXAMPLES:
    Bot: intervals = [100ms, 100ms, 100ms]
         CV = 0.0
         regularity = 1.0 - (0.0/2.0) = 1.0 → VERY regular

    Human: intervals = [2s, 500ms, 15s, 200ms]
           CV = 1.2
           regularity = 1.0 - (1.2/2.0) = 0.4 → somewhat irregular

    Very random: intervals = [1s, 30s, 0.1s, 60s]
                 CV = 2.5
                 regularity = 1.0 - (2.5/2.0) = -0.25 → clamped to 0.0

    WHY 5 MINIMUM:
    With fewer than 5 timestamps, we only have 3-4 intervals.
    Too few to reliably measure regularity. Could be coincidence.
    """
    if len(timestamps) < 5:
        return 0.0

    sorted_ts = sorted(timestamps)

    # Compute time gaps between consecutive requests
    intervals = [
        sorted_ts[i + 1] - sorted_ts[i]
        for i in range(len(sorted_ts) - 1)
    ]

    # Remove zero intervals (simultaneous requests)
    intervals = [i for i in intervals if i > 0]

    if not intervals:
        # All requests at the same instant = perfectly regular
        return 1.0

    mean_interval = sum(intervals) / len(intervals)
    if mean_interval == 0:
        return 1.0

    # CV of intervals
    variance = sum(
        (i - mean_interval) ** 2 for i in intervals
    ) / len(intervals)
    cv = math.sqrt(variance) / mean_interval

    # Transform: low CV → high regularity
    # CV = 0 → regularity = 1.0 (bot)
    # CV = 1 → regularity = 0.5 (ambiguous)
    # CV = 2+ → regularity = 0.0 (human)
    regularity = max(0.0, min(1.0, 1.0 - (cv / 2.0)))
    return round(regularity, 4)


def detect_anomaly(
    fingerprint_velocity: float,
    population_velocities: list[float],
    timestamps: list[float],
    zscore_threshold: float = 2.0,
) -> AnomalyResult:
    """
    Combined anomaly detection.

    LOGIC:
    1. Compute Z-score (is velocity abnormal?)
    2. Compute interval regularity (is timing bot-like?)
    3. Combine:
       - Z > threshold → anomalous (speed is unusual)
       - Z > 1.5 AND regularity > 0.8 → anomalous
         (somewhat fast AND very regular = bot)
       - Otherwise → normal

    WHY THE COMBINATION:
    Z-score 2.5 AND regularity 0.9 = almost certainly bot
    Z-score 2.5 BUT regularity 0.2 = might just be a
      busy legitimate user clicking fast

    The regularity check confirms the Z-score signal.
    """
    zscore = compute_zscore(
        fingerprint_velocity, population_velocities
    )
    regularity = compute_interval_regularity(timestamps)

    evidence = []
    is_anomalous = False

    # Check Z-score
    if abs(zscore) > zscore_threshold:
        is_anomalous = True
        evidence.append(
            f"Z-score {zscore:.2f} exceeds threshold "
            f"{zscore_threshold} "
            f"(request rate is {zscore:.1f}x standard "
            f"deviations above average)"
        )

    # Check regularity (only flag if Z-score is also elevated)
    if regularity > 0.8:
        evidence.append(
            f"Request interval regularity {regularity:.2f} "
            f"(bot-like — threshold 0.80)"
        )
        # Regular timing + somewhat elevated speed = bot
        if zscore > 1.5:
            is_anomalous = True

    if not evidence:
        evidence.append("No anomalies detected")

    return AnomalyResult(
        zscore=zscore,
        regularity_score=regularity,
        is_anomalous=is_anomalous,
        evidence=evidence,
    )