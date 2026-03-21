"""
Tests for cold start phase management.

We test the phase logic and threshold values WITHOUT
needing Redis (by directly setting start_time).
"""

from datetime import datetime, timezone, timedelta

from Vigil.core.cold_start import ColdStartManager


class TestColdStartPhases:
    """Verify correct phase based on elapsed time."""

    def test_fresh_start_is_learning_phase(self):
        """Brand new deployment should be in learning mode."""
        manager = ColdStartManager()
        manager.start_time = datetime.now(timezone.utc)
        assert manager.get_phase() == "learning"

    def test_after_one_hour_is_cautious(self):
        """After 1 hour, should transition to cautious."""
        manager = ColdStartManager()
        manager.start_time = (
            datetime.now(timezone.utc) - timedelta(hours=2)
        )
        assert manager.get_phase() == "cautious"

    def test_after_24_hours_is_normal(self):
        """After 24 hours, should be in normal mode."""
        manager = ColdStartManager()
        manager.start_time = (
            datetime.now(timezone.utc) - timedelta(hours=25)
        )
        assert manager.get_phase() == "normal"

    def test_just_before_learning_ends(self):
        """At 59 minutes, still learning."""
        manager = ColdStartManager()
        manager.start_time = (
            datetime.now(timezone.utc) - timedelta(minutes=59)
        )
        assert manager.get_phase() == "learning"

    def test_just_after_cautious_starts(self):
        """At 61 minutes, should be cautious."""
        manager = ColdStartManager()
        manager.start_time = (
            datetime.now(timezone.utc) - timedelta(minutes=61)
        )
        assert manager.get_phase() == "cautious"


class TestColdStartThresholds:
    """Verify thresholds are appropriate for each phase."""

    def test_learning_has_highest_velocity_limit(self):
        """Learning mode should tolerate highest RPM."""
        manager = ColdStartManager()
        manager.start_time = datetime.now(timezone.utc)
        thresholds = manager.get_thresholds()
        assert thresholds.velocity_hard_limit == 500
        assert thresholds.phase == "learning"

    def test_cautious_has_medium_velocity_limit(self):
        manager = ColdStartManager()
        manager.start_time = (
            datetime.now(timezone.utc) - timedelta(hours=2)
        )
        thresholds = manager.get_thresholds()
        assert thresholds.velocity_hard_limit == 300
        assert thresholds.phase == "cautious"

    def test_normal_uses_configured_limit(self):
        manager = ColdStartManager()
        manager.start_time = (
            datetime.now(timezone.utc) - timedelta(hours=25)
        )
        thresholds = manager.get_thresholds()
        assert thresholds.velocity_hard_limit == 200
        assert thresholds.phase == "normal"

    def test_learning_block_threshold_is_strictest(self):
        """In learning mode, only block very high scores."""
        manager = ColdStartManager()
        manager.start_time = datetime.now(timezone.utc)
        thresholds = manager.get_thresholds()
        assert thresholds.block_score_threshold == 0.95

    def test_normal_block_threshold_is_standard(self):
        manager = ColdStartManager()
        manager.start_time = (
            datetime.now(timezone.utc) - timedelta(hours=25)
        )
        thresholds = manager.get_thresholds()
        assert thresholds.block_score_threshold == 0.85

    def test_thresholds_decrease_over_phases(self):
        """Block threshold should decrease as we gain confidence."""
        manager = ColdStartManager()

        # Learning
        manager.start_time = datetime.now(timezone.utc)
        learning = manager.get_thresholds()

        # Cautious
        manager.start_time = (
            datetime.now(timezone.utc) - timedelta(hours=2)
        )
        cautious = manager.get_thresholds()

        # Normal
        manager.start_time = (
            datetime.now(timezone.utc) - timedelta(hours=25)
        )
        normal = manager.get_thresholds()

        # Learning should be most relaxed (highest thresholds)
        assert learning.block_score_threshold >= cautious.block_score_threshold
        assert cautious.block_score_threshold >= normal.block_score_threshold