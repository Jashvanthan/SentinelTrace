"""
SentinelTrace Backend — SQLAlchemy Declarative Base
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass


# ── SQLite Compatibility Compilers for PostgreSQL Dialect Types ─────────────
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB, UUID, INET, ARRAY as PG_ARRAY
from sqlalchemy.types import ARRAY as GENERIC_ARRAY

@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(element, compiler, **kw):
    return "JSON"

@compiles(UUID, "sqlite")
def _compile_uuid_sqlite(element, compiler, **kw):
    return "VARCHAR(36)"

@compiles(INET, "sqlite")
def _compile_inet_sqlite(element, compiler, **kw):
    return "VARCHAR(45)"

@compiles(PG_ARRAY, "sqlite")
@compiles(GENERIC_ARRAY, "sqlite")
def _compile_array_sqlite(element, compiler, **kw):
    return "JSON"


class TimestampMixin:
    """Adds created_at / updated_at timestamps to any model."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class UUIDPrimaryKeyMixin:
    """Adds a UUID primary key column."""

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )
