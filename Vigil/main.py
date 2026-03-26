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
"""
Main FastAPI application — the entry point.

ALL routes registered here. When you add a new endpoint
file, import its router and include it below.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from Vigil.config import logger
from Vigil.db.engine import init_db, close_db
from Vigil.cache.client import init_redis, close_redis
from Vigil.core.cold_start import cold_start
from Vigil.core.setup import ensure_default_organization
from Vigil.api.middleware import rate_limit_vigil


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    await init_db()
    await init_redis()
    await cold_start.initialize()
    await ensure_default_organization()
    logger.info("Vigil started — all connections ready")

    yield

    await close_db()
    await close_redis()
    logger.info("Vigil shut down cleanly")


app = FastAPI(
    title="Vigil",
    description="API Abuse Detection Engine",
    version="1.0.0",
    lifespan=lifespan,
    dependencies=[Depends(rate_limit_vigil)],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Import and register all route modules ──
from Vigil.api.analyze import router as analyze_router
from Vigil.api.fingerprints import (
    router as fingerprints_router,
)
from Vigil.api.attacks import router as attacks_router
from Vigil.api.analytics import (
    router as analytics_router,
)
from Vigil.api.feedback import router as feedback_router
from Vigil.api.websocket import router as ws_router

app.include_router(analyze_router)
app.include_router(fingerprints_router)
app.include_router(attacks_router)
app.include_router(analytics_router)
app.include_router(feedback_router)
app.include_router(ws_router)


@app.get("/health")
async def health_check():
    """Returns 200 if server is running."""
    return {"status": "healthy", "service": "Vigil"}