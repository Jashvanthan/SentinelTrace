"""
SentinelTrace Backend — SQLAlchemy Async Session Factory
"""
from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings

settings = get_settings()

engine_kwargs: dict[str, Any] = {
    "echo": settings.is_development,
    "pool_pre_ping": True,
}

from sqlalchemy import event

if not settings.DATABASE_URL.startswith("sqlite"):
    engine_kwargs.update({
        "pool_size": settings.DATABASE_POOL_SIZE,
        "max_overflow": settings.DATABASE_MAX_OVERFLOW,
        "pool_timeout": 30,
        "pool_recycle": 1800,  # Auto-recycle stale connections every 30 minutes
        "pool_pre_ping": True, # Proactively test connection validity before checkout
        "connect_args": {
            "command_timeout": 30,
            "server_settings": {
                "application_name": "sentineltrace_api",
            },
        },
    })
else:
    engine_kwargs["connect_args"] = {
        "timeout": 60,
        "check_same_thread": False,
    }

engine = create_async_engine(settings.DATABASE_URL, **engine_kwargs)

if settings.DATABASE_URL.startswith("sqlite"):
    import datetime as dt
    from sqlalchemy import types
    from sqlalchemy.dialects.sqlite.base import DATETIME
    from sqlalchemy.dialects.sqlite.pysqlite import _SQLite_pysqliteTimeStamp

    class SQLiteUTCDateTime(DATETIME):
        def result_processor(self, dialect, coltype):
            base_processor = super().result_processor(dialect, coltype)
            def process(value):
                if base_processor:
                    value = base_processor(value)
                if isinstance(value, dt.datetime) and value.tzinfo is None:
                    return value.replace(tzinfo=dt.timezone.utc)
                return value
            return process

    class SQLiteUTCTimestamp(_SQLite_pysqliteTimeStamp):
        def result_processor(self, dialect, coltype):
            base_processor = super().result_processor(dialect, coltype)
            def process(value):
                if base_processor:
                    value = base_processor(value)
                if isinstance(value, dt.datetime) and value.tzinfo is None:
                    return value.replace(tzinfo=dt.timezone.utc)
                return value
            return process

    engine.dialect.colspecs[types.DateTime] = SQLiteUTCDateTime
    engine.dialect.colspecs[DATETIME] = SQLiteUTCDateTime
    engine.dialect.colspecs[types.TIMESTAMP] = SQLiteUTCTimestamp
    engine.dialect.colspecs[_SQLite_pysqliteTimeStamp] = SQLiteUTCTimestamp

    @event.listens_for(engine.sync_engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        # High-concurrency WAL mode and memory cache
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=15000")   # Prevent database locked crashes (wait up to 15s)
        cursor.execute("PRAGMA foreign_keys=ON")      # Enforce referential integrity & cascading
        cursor.execute("PRAGMA cache_size=-64000")    # 64MB memory page cache for fast queries
        cursor.execute("PRAGMA temp_store=MEMORY")    # Fast in-memory temporary tables & indices
        cursor.close()


AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async database session with automatic transaction management."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def check_db_health() -> bool:
    """Execute lightweight ping to verify database responsiveness."""
    from sqlalchemy import text
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(text("SELECT 1"))
            return result.scalar() == 1
    except Exception:
        return False


async def cleanup_expired_sessions() -> int:
    """
    Periodic storage optimization: purge expired or revoked refresh sessions
    older than 7 days to keep database tables lean and indices performant.
    """
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import delete
    from app.models.refresh_session import RefreshSession

    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    try:
        async with AsyncSessionLocal() as session:
            stmt = delete(RefreshSession).where(
                (RefreshSession.revoked.is_(True)) | (RefreshSession.expires_at < cutoff)
            )
            result = await session.execute(stmt)
            await session.commit()
            return result.rowcount or 0
    except Exception:
        return 0

