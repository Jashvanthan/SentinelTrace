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
    engine_kwargs["pool_size"] = settings.DATABASE_POOL_SIZE
    engine_kwargs["max_overflow"] = settings.DATABASE_MAX_OVERFLOW
else:
    engine_kwargs["connect_args"] = {"timeout": 60}

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
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()


AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
