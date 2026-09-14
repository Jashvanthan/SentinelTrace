"""
SentinelTrace Backend — Google Pending Registration Nonce Model

Tracks short-lived, single-use nonces that bridge Google OAuth identity
verification and SentinelTrace account creation.

Security properties:
- consumed flag ensures single-use (atomically updated)
- expires_at enforces 5-minute TTL
- google_sub ties nonce to the exact Google identity
- DB unique constraint on nonce prevents replay
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class GooglePendingNonce(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "google_pending_nonces"

    nonce: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    google_sub: Mapped[str] = mapped_column(String(256), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    full_name: Mapped[str] = mapped_column(String(256), nullable=False)
    picture: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    def __repr__(self) -> str:
        return f"<GooglePendingNonce nonce={self.nonce[:8]}... consumed={self.consumed}>"
