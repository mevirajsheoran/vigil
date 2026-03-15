"""
Application configuration and structured logging.

This file does two things:
1. Reads settings from environment variables (or .env file)
2. Sets up JSON logging (structured logs instead of print statements)

WHY PYDANTIC-SETTINGS:
Without it, if DATABASE_URL is missing, you'd get a cryptic error
30 seconds later: "connection refused". With pydantic-settings,
the app crashes IMMEDIATELY on startup with:
"Field 'database_url' is required"
Much easier to debug.

WHY JSON LOGGING:
print("Request blocked") → hard to search, hard to filter
logger.info("Request blocked", extra={"fingerprint": "a1b2"})
→ {"asctime": "2025-01-15", "message": "Request blocked",
   "fingerprint": "a1b2"}
→ searchable, filterable, parseable by monitoring tools
"""

import logging

from pydantic_settings import BaseSettings, SettingsConfigDict
from pythonjsonlogger import jsonlogger


class Settings(BaseSettings):
    """
    Every attribute here becomes a setting that can be
    overridden by an environment variable of the SAME NAME
    (case-insensitive).

    Example:
        database_url = "default_value"

    Can be overridden by:
        DATABASE_URL=some_other_value in .env
        or: export DATABASE_URL=some_other_value in terminal
    """

    # Tells pydantic-settings to read from .env file
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )

    # ── Database ──
    # asyncpg driver for FastAPI (async operations)
    database_url: str = (
        "postgresql+asyncpg://Vigil:Vigil"
        "@localhost:5432/Vigil"
    )
    # psycopg2 driver for Alembic (sync migrations)
    database_url_sync: str = (
        "postgresql://Vigil:Vigil"
        "@localhost:5432/Vigil"
    )

    # ── Redis ──
    redis_url: str = "redis://localhost:6379"

    # ── AI ──
    # Only needed for attack analysis. App works without it.
    gemini_api_key: str = ""

    # ── Detection Thresholds ──
    # Score >= 0.85 → BLOCK the request
    block_threshold: float = 0.85
    # Score >= 0.65 → CHALLENGE (rate limit + retry-after)
    challenge_threshold: float = 0.65
    # Score >= 0.40 → MONITOR (log but allow)
    monitor_threshold: float = 0.40

    # Max requests per minute before auto-block
    velocity_hard_limit: int = 200

    # ── Cold Start ──
    # First 1 hour: learning mode (very relaxed thresholds)
    cold_start_learning_hours: float = 1.0
    # Hours 1-24: cautious mode (slightly relaxed)
    cold_start_cautious_hours: float = 24.0

    # ── Server ──
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = True


# Create ONE instance. Import this everywhere.
# Don't create new Settings() objects — just import this one.
settings = Settings()


def _setup_logging() -> logging.Logger:
    """
    Configure structured JSON logging.

    This REPLACES all print() statements in the codebase.
    Every log line is a JSON object that monitoring tools
    can parse, search, and alert on.
    """
    _logger = logging.getLogger("Vigil")

    # Guard: don't add duplicate handlers if this function
    # is called twice (happens during testing)
    if not _logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            jsonlogger.JsonFormatter(
                "%(asctime)s %(levelname)s %(name)s %(message)s"
            )
        )
        _logger.addHandler(handler)

    _logger.setLevel(logging.INFO)
    return _logger


# Create ONE logger. Import this everywhere.
logger = _setup_logging()