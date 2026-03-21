"""
Cold start management — graduated thresholds during warmup.

THE PROBLEM:
Fresh deployment = zero data. Z-scores need population data.
Pattern detection needs history. Everything looks "normal"
because there's no baseline to compare against.

If we used normal thresholds immediately, we'd either:
1. Block too many legitimate users (thresholds too low)
2. Miss actual attacks (thresholds too high)

SOLUTION:
Start with very high thresholds (only catch obvious attacks),
then gradually tighten as we accumulate data.

Phase 1: LEARNING (first 1 hour)
  → Only block if RPM > 500 or threat score > 0.95
  → Very few false positives, might miss subtle attacks

Phase 2: CAUTIOUS (hours 1-24)
  → Block if RPM > 300 or threat score > 0.85
  → Starting to trust our data

Phase 3: NORMAL (after 24 hours)
  → Block if RPM > 200 or threat score > 0.85
  → Full sensitivity, enough data for reliable detection

WHY PERSIST TO REDIS:
Server restarts shouldn't reset the phase.
If we've been running for 12 hours, we should stay
in "cautious" mode, not go back to "learning."
"""

from datetime import datetime, timezone, timedelta
from dataclasses import dataclass

from Vigil.config import settings, logger
from Vigil.cache.client import get_redis


@dataclass
class Thresholds:
    """Current detection thresholds based on phase."""
    velocity_hard_limit: int
    block_score_threshold: float
    challenge_score_threshold: float
    phase: str


class ColdStartManager:
    """
    Manages cold start phases and returns appropriate
    thresholds based on how long Vigil has been running.
    """

    def __init__(self) -> None:
        # Will be set by initialize() from Redis
        self.start_time: datetime = datetime.now(timezone.utc)

    async def initialize(self) -> None:
        """
        Load or set start_time from Redis.

        Called once during app startup (in main.py lifespan).
        If Redis already has a start time (from a previous run),
        use that. Otherwise, store the current time.
        """
        redis = get_redis()
        stored = await redis.get("vigil:cold_start_time")

        if stored:
            # Previous run exists — continue from where we were
            self.start_time = datetime.fromisoformat(stored)
            logger.info(
                "Cold start: resumed from previous run",
                extra={
                    "start_time": stored,
                    "phase": self.get_phase(),
                },
            )
        else:
            # Fresh deployment — start learning
            self.start_time = datetime.now(timezone.utc)
            await redis.set(
                "vigil:cold_start_time",
                self.start_time.isoformat(),
            )
            logger.info(
                "Cold start: fresh deployment, entering learning phase"
            )

    def get_phase(self) -> str:
        """
        Determine current phase based on elapsed time.

        Returns: "learning", "cautious", or "normal"
        """
        age = datetime.now(timezone.utc) - self.start_time

        if age < timedelta(
            hours=settings.cold_start_learning_hours
        ):
            return "learning"
        elif age < timedelta(
            hours=settings.cold_start_cautious_hours
        ):
            return "cautious"
        return "normal"

    def get_thresholds(self) -> Thresholds:
        """
        Get current detection thresholds.

        Each phase has different thresholds:
        - Learning: very relaxed (avoid false positives)
        - Cautious: moderate (building confidence)
        - Normal: standard (full sensitivity)
        """
        phase = self.get_phase()

        if phase == "learning":
            return Thresholds(
                velocity_hard_limit=500,
                block_score_threshold=0.95,
                challenge_score_threshold=0.85,
                phase=phase,
            )
        elif phase == "cautious":
            return Thresholds(
                velocity_hard_limit=300,
                block_score_threshold=0.85,
                challenge_score_threshold=0.70,
                phase=phase,
            )
        else:
            return Thresholds(
                velocity_hard_limit=settings.velocity_hard_limit,
                block_score_threshold=settings.block_threshold,
                challenge_score_threshold=settings.challenge_threshold,
                phase=phase,
            )


# Singleton — import this in other files
cold_start = ColdStartManager()