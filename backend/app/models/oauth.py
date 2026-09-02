"""
SentinelTrace Backend — OAuth Models
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ExternalIdentity(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "external_identities"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_subject: Mapped[str] = mapped_column(String(256), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)

    __table_args__ = (
        UniqueConstraint("provider", "provider_subject", name="uq_provider_subject"),
    )

    user: Mapped["User"] = relationship("User", back_populates="external_identities")  # type: ignore

    def __repr__(self) -> str:
        return f"<ExternalIdentity id={self.id} user={self.user_id} provider={self.provider}>"


class OAuthState(Base):
    __tablename__ = "oauth_states"

    state: Mapped[str] = mapped_column(String(128), primary_key=True)
    browser_nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def __repr__(self) -> str:
        return f"<OAuthState state={self.state}>"
