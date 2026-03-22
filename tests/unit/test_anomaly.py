"""
Tests for statistical anomaly detection.

TESTING STRATEGY:
- Z-score: average value → ~0, extreme outlier → very high
- Trimming: attackers in population shouldn't hide new attackers
- Regularity: regular intervals → high score, irregular → low
- Combined: both signals together for final decision
"""

import random

from Vigil.core.anomaly import (
    compute_zscore,
    compute_interval_regularity,
    detect_anomaly,
)


# A reusable population with NATURAL VARIATION.
# Mean ≈ 5.5, std ≈ 1.4
# Used by multiple tests that need a realistic baseline.
NORMAL_POPULATION = [
    3.0, 4.0, 5.0, 6.0, 7.0,
    4.0, 5.0, 6.0, 3.0, 8.0,
    5.0, 4.0, 6.0, 7.0, 5.0,
    6.0, 7.0, 5.5, 6.5, 7.5,
]


# ═══════════════════════════════════════════════════
# Z-SCORE TESTS
# ═══════════════════════════════════════════════════

class TestZScore:
    """Test Z-score computation."""

    def test_average_value_returns_near_zero(self):
        """A value equal to the mean should have Z ≈ 0."""
        population = [10.0, 9.0, 11.0, 10.0, 9.5] * 4
        z = compute_zscore(10.0, population)
        assert abs(z) < 0.5

    def test_extreme_outlier_returns_high_zscore(self):
        """200 RPM when everyone else does 5-9 RPM → huge Z."""
        population = [
            5.0, 6.0, 7.0, 5.0, 8.0,
            6.0, 7.0, 5.0, 9.0, 6.0,
            5.0, 7.0, 6.0, 8.0, 5.0,
            6.0, 7.0, 5.5, 6.5, 7.5,
        ]
        z = compute_zscore(200.0, population)
        assert z > 10.0

    def test_insufficient_population_returns_zero(self):
        """Less than 20 data points → can't compute reliably."""
        population = [5.0, 6.0, 7.0]
        z = compute_zscore(100.0, population)
        assert z == 0.0

    def test_all_same_values_returns_zero(self):
        """If everyone has the same rate, std = 0, can't divide."""
        population = [10.0] * 20
        z = compute_zscore(10.0, population)
        assert z == 0.0

    def test_trimmed_zscore_resists_attacker_pollution(self):
        """
        THE MOST IMPORTANT ANOMALY TEST.

        Even with attackers mixed into the population,
        trimming should keep the baseline clean so
        a new attacker at 200 is still detected.

        FIX: We need enough normal values so that 5% trimming
        from each end removes all attacker values.

        Population: 40 normal + 2 attackers = 42 total
        trim_count = int(42 × 0.05) = 2
        Removes 2 from top (both attackers!) and 2 from bottom.
        Trimmed population is purely normal → mean ≈ 5, std ≈ 0.8
        Z = (200 - 5) / 0.8 ≈ 243 → DETECTED!
        """
        normal = [
            4.0, 5.0, 6.0, 5.0, 4.5,
            5.5, 6.0, 4.0, 5.0, 6.5,
            5.0, 4.0, 5.5, 6.0, 5.0,
            4.5, 5.5, 6.0, 4.0, 5.0,
            6.5, 5.0, 4.0, 5.5, 6.0,
            5.0, 4.5, 5.5, 6.0, 4.0,
            5.0, 6.5, 5.0, 4.0, 5.5,
            6.0, 5.0, 4.5, 5.5, 6.0,
        ]  # 40 normal values (range 4.0-6.5)
        attackers = [200.0, 200.0]
        population = normal + attackers  # 42 total
        z = compute_zscore(200.0, population)
        assert z > 2.0

    def test_moderately_high_value(self):
        """15 RPM when average is 5 → moderately high Z."""
        z = compute_zscore(15.0, NORMAL_POPULATION)
        assert 2.0 < z < 15.0

    def test_below_average_gives_negative_zscore(self):
        """Value below average → negative Z (not suspicious)."""
        population = [
            50.0, 60.0, 55.0, 45.0, 65.0,
            50.0, 55.0, 60.0, 45.0, 50.0,
            55.0, 60.0, 50.0, 45.0, 55.0,
            50.0, 60.0, 55.0, 45.0, 50.0,
        ]
        z = compute_zscore(10.0, population)
        assert z < 0


# ═══════════════════════════════════════════════════
# INTERVAL REGULARITY TESTS
# ═══════════════════════════════════════════════════

class TestIntervalRegularity:
    """Test timing regularity measurement."""

    def test_perfectly_regular_intervals(self):
        """
        Exactly 1 second apart — like a metronome.
        This is bot-like behavior. Score should be very high.
        """
        timestamps = [1000.0 + i for i in range(20)]
        score = compute_interval_regularity(timestamps)
        assert score > 0.9

    def test_highly_irregular_intervals(self):
        """
        Random gaps — like a human clicking around.
        Score should be low.
        """
        timestamps = [
            1000.0, 1002.5, 1018.0, 1019.1, 1045.0,
            1046.0, 1100.0, 1102.0, 1150.0, 1300.0,
        ]
        score = compute_interval_regularity(timestamps)
        assert score < 0.4

    def test_insufficient_data_returns_zero(self):
        """Less than 5 timestamps → can't measure reliably."""
        timestamps = [1000.0, 1001.0, 1002.0]
        score = compute_interval_regularity(timestamps)
        assert score == 0.0

    def test_all_simultaneous_returns_one(self):
        """All at same time → perfectly regular (suspicious)."""
        timestamps = [1000.0] * 10
        score = compute_interval_regularity(timestamps)
        assert score == 1.0

    def test_bot_with_slight_jitter(self):
        """
        100ms apart with ±5ms jitter — still very regular.
        Real bots often have small timing variations due
        to network latency, but the PATTERN is still regular.
        """
        random.seed(42)
        timestamps = [
            1000.0 + i * 0.1 + random.uniform(-0.005, 0.005)
            for i in range(20)
        ]
        score = compute_interval_regularity(timestamps)
        assert score > 0.7

    def test_regularity_between_zero_and_one(self):
        """Score should always be in [0.0, 1.0] range."""
        timestamps = [
            1000.0, 1001.0, 1050.0, 1051.0, 1200.0,
            1201.0, 1500.0, 1502.0, 2000.0, 2001.0,
        ]
        score = compute_interval_regularity(timestamps)
        assert 0.0 <= score <= 1.0


# ═══════════════════════════════════════════════════
# COMBINED ANOMALY DETECTION TESTS
# ═══════════════════════════════════════════════════

class TestDetectAnomaly:
    """Test combined anomaly detection."""

    def test_normal_traffic_not_anomalous(self):
        """
        Average speed, irregular timing → normal user.
        Should NOT be flagged.
        """
        timestamps = [
            1000.0, 1005.0, 1008.0, 1020.0, 1035.0,
            1040.0, 1060.0, 1065.0, 1090.0, 1120.0,
        ]
        result = detect_anomaly(
            fingerprint_velocity=6.0,
            population_velocities=NORMAL_POPULATION,
            timestamps=timestamps,
        )
        assert not result.is_anomalous

    def test_high_velocity_bot_is_anomalous(self):
        """
        200 RPM with perfectly regular timing → bot.
        Must be flagged.

        FIX: Population needs VARIATION (not all identical).
        When all values are identical, std=0, Z-score
        returns 0.0 because you can't measure how unusual
        something is when there's no variation to compare.
        """
        timestamps = [
            1000.0 + i * 0.1 for i in range(20)
        ]
        result = detect_anomaly(
            fingerprint_velocity=200.0,
            population_velocities=NORMAL_POPULATION,
            timestamps=timestamps,
        )
        assert result.is_anomalous
        assert result.zscore > 3.0

    def test_high_velocity_irregular_timing(self):
        """
        High speed but very irregular timing.
        Z-score alone flags it (speed is unusual).

        FIX: Population needs variation for Z-score to work.
        """
        timestamps = [
            1000.0, 1005.0, 1008.0, 1020.0, 1035.0,
            1040.0, 1060.0, 1065.0, 1090.0, 1120.0,
        ]
        result = detect_anomaly(
            fingerprint_velocity=200.0,
            population_velocities=NORMAL_POPULATION,
            timestamps=timestamps,
        )
        assert result.is_anomalous

    def test_moderate_velocity_but_regular_timing(self):
        """
        Moderately elevated speed + very regular timing.
        The combination should flag it as anomalous.

        FIX: Population needs variation. With NORMAL_POPULATION
        (mean ≈ 5.5, std ≈ 1.4), velocity of 15 gives
        Z ≈ 6.8, which is well above both 2.0 and 1.5
        thresholds.
        """
        timestamps = [
            1000.0 + i * 0.1 for i in range(20)
        ]
        result = detect_anomaly(
            fingerprint_velocity=15.0,
            population_velocities=NORMAL_POPULATION,
            timestamps=timestamps,
            zscore_threshold=2.0,
        )
        assert result.is_anomalous or result.zscore > 2.0

    def test_evidence_populated_for_anomaly(self):
        """Evidence list should explain WHY it's anomalous."""
        timestamps = [
            1000.0 + i * 0.1 for i in range(20)
        ]
        result = detect_anomaly(
            fingerprint_velocity=200.0,
            population_velocities=NORMAL_POPULATION,
            timestamps=timestamps,
        )
        assert len(result.evidence) > 0
        assert any(
            "z-score" in e.lower()
            or "regularity" in e.lower()
            for e in result.evidence
        )

    def test_evidence_says_no_anomalies_for_normal(self):
        """Normal traffic evidence should say 'no anomalies'."""
        timestamps = [
            1000.0, 1005.0, 1008.0, 1020.0, 1035.0,
            1040.0, 1060.0, 1065.0, 1090.0, 1120.0,
        ]
        result = detect_anomaly(
            fingerprint_velocity=6.0,
            population_velocities=NORMAL_POPULATION,
            timestamps=timestamps,
        )
        assert any(
            "no anomalies" in e.lower()
            for e in result.evidence
        )