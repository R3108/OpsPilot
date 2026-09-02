"""Async SQLAlchemy engine / session plumbing."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def use_compatible_event_loop() -> None:
    """Ask for a SelectorEventLoop on Windows.

    psycopg's async pool refuses to run on the ProactorEventLoop that
    ``asyncio.run`` gives you on Windows, so the LangGraph Postgres
    checkpointer just times out acquiring a connection — which takes down
    every investigation, not just the checkpoint write.

    uvicorn already selects a compatible loop; entrypoints that drive the loop
    themselves (the CLI, the arq worker) must ask for one. Call this before the
    loop is created. A no-op everywhere but Windows.
    """
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def _build_engine() -> AsyncEngine:
    url = settings.database_url
    kwargs: dict[str, object] = {
        "echo": settings.db_echo,
        "future": True,
        "pool_pre_ping": True,
    }

    if not url.startswith("sqlite"):
        kwargs.update(
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_recycle=1800,
        )
        return create_async_engine(url, **kwargs)  # type: ignore[arg-type]

    kwargs.pop("pool_pre_ping")
    if ":memory:" in url:
        # An in-memory database only exists for as long as its connection, so
        # every session has to share one. That serialises writes, which is fine
        # for unit tests but cannot represent the concurrent sessions the
        # investigator fan-out actually uses — file-backed sqlite below is what
        # the integration tests run on.
        from sqlalchemy.pool import StaticPool

        kwargs.update(poolclass=StaticPool, connect_args={"check_same_thread": False})
        return create_async_engine(url, **kwargs)  # type: ignore[arg-type]

    # File-backed sqlite: real per-session connections, so concurrent nodes
    # behave the way they will on Postgres.
    from sqlalchemy import event
    from sqlalchemy.pool import NullPool

    kwargs.update(
        poolclass=NullPool,
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    engine = create_async_engine(url, **kwargs)  # type: ignore[arg-type]

    @event.listens_for(engine.sync_engine, "connect")
    def _configure_sqlite(dbapi_connection, _record):  # noqa: ANN001, ANN202
        cursor = dbapi_connection.cursor()
        # WAL lets readers and a writer coexist; the busy timeout makes a
        # concurrent writer wait rather than immediately raising "database is
        # locked".
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = _build_engine()
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
    return _sessionmaker


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Transactional scope for background work (workers, agent nodes, CLI)."""
    async with get_sessionmaker()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency. Commits on a clean request, rolls back otherwise."""
    async with get_sessionmaker()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None


async def check_database() -> bool:
    from sqlalchemy import text

    try:
        async with get_engine().connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        log.warning("db.healthcheck_failed", error=str(exc))
        return False
    return True
