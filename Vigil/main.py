"""
Main FastAPI application — the entry point.

STARTUP SEQUENCE:
1. Connect to PostgreSQL → verify with SELECT 1
2. Connect to Redis → verify with PING
3. Create default organization if it doesn't exist
4. Log "ready" message

SHUTDOWN SEQUENCE:
1. Close PostgreSQL connections (return them to the pool)
2. Close Redis connection
3. Log "shut down" message

The lifespan context manager ensures cleanup happens
even if the server crashes. Without it, connections
would leak and eventually exhaust the database.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from Vigil.config import logger
from Vigil.db.engine import init_db, close_db
from Vigil.cache.client import init_redis, close_redis
from Vigil.core.setup import ensure_default_organization
from Vigil.api.middleware import rate_limit_vigil


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup and shutdown lifecycle.

    Everything BEFORE yield runs on startup.
    Everything AFTER yield runs on shutdown.
    The yield itself is when the app is "live" and
    accepting requests.
    """
    # ── STARTUP ──
    await init_db()       # Connect to PostgreSQL
    await init_redis()    # Connect to Redis
    await ensure_default_organization()
    logger.info("Vigil started — all connections ready")

    yield  # App is now running and handling requests

    # ── SHUTDOWN ──
    await close_db()
    await close_redis()
    logger.info("Vigil shut down cleanly")


app = FastAPI(
    title="Vigil",
    description="API Abuse Detection Engine",
    version="1.0.0",
    lifespan=lifespan,
    # This makes rate_limit_vigil run on EVERY request
    # to ALL endpoints automatically
    dependencies=[Depends(rate_limit_vigil)],
)

# CORS configuration — allow React dashboard to call our API
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  # Vite dev server (React)
        "http://localhost:3000",  # Alternative React port
        "http://localhost:8000",  # Same-origin (Swagger UI)
    ],
    allow_credentials=True,
    allow_methods=["*"],     # Allow GET, POST, PUT, DELETE, etc.
    allow_headers=["*"],     # Allow any HTTP headers
)


@app.get("/health")
async def health_check():
    """
    Simple health check endpoint.

    Returns 200 if the server is running.
    Used by:
    - Docker healthcheck (is the container alive?)
    - Monitoring tools (is the service up?)
    - You, right now, to verify everything works
    """
    return {"status": "healthy", "service": "Vigil"}