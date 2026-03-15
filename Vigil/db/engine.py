"""
Database engine setup using SQLAlchemy 2.0 async.

CONCEPTS:
- Engine: manages the connection pool to PostgreSQL
- Session: one "conversation" with the database
  (query, insert, update — then close)
- SessionMaker: factory that creates new sessions

WHY ASYNC:
FastAPI handles many requests at the same time (concurrently).
If we used a SYNC database driver, every request would BLOCK
the entire server while waiting for PostgreSQL to respond.
Async means: "go ask PostgreSQL, and while waiting, handle
other requests." Much better throughput.
"""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import text

from Vigil.config import settings, logger


# The engine manages a POOL of database connections.
# Instead of opening a new connection for every request
# (slow — ~50ms each), the pool keeps 20 connections
# open and reuses them.
engine = create_async_engine(
    settings.database_url,

    # echo=True prints every SQL query to console.
    # Useful for debugging, turn off in production.
    echo=settings.debug,

    # Keep 20 connections ready at all times
    pool_size=20,

    # Allow up to 10 more if all 20 are busy
    max_overflow=10,

    # If all 30 connections are busy, wait up to 30 seconds
    # before raising an error
    pool_timeout=30,

    # Recycle (close and reopen) connections after 1 hour
    # to prevent stale connections
    pool_recycle=3600,
)

# Factory that creates database sessions.
# Think of it as a template: "every session should be
# async and shouldn't expire data after commit."
async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db() -> None:
    """
    Verify database connectivity on startup.

    Runs a simple "SELECT 1" to confirm PostgreSQL is
    reachable. If this fails, the app crashes on startup
    with a clear error instead of failing randomly later.
    """
    async with engine.begin() as conn:
        await conn.execute(text("SELECT 1"))
    logger.info("Database connection verified")


async def close_db() -> None:
    """
    Close all database connections on shutdown.

    Without this, connections would leak — PostgreSQL
    would eventually refuse new connections because
    the old ones are still "open" from the app's
    perspective but actually dead.
    """
    await engine.dispose()
    logger.info("Database connections closed")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency injection for FastAPI routes.

    FastAPI calls this function automatically when a
    route needs a database session. The session is
    created, given to the route, and closed after
    the route finishes (even if it crashes).

    Usage in a route:
        @app.get("/something")
        async def my_route(db: AsyncSession = Depends(get_db)):
            result = await db.execute(select(MyModel))
            return result.scalars().all()
    """
    async with async_session() as session:
        yield session