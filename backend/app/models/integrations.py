"""
SentinelTrace Backend — Integration Models (e.g. Gmail)
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, ARRAY
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class GmailConnection(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "gmail_connections"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    email_address: Mapped[str] = mapped_column(String(320), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), default="google", nullable=False)
    
    # Store Google OAuth tokens securely using application-level encryption
    encrypted_access_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    encrypted_refresh_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scopes: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    
    status: Mapped[str] = mapped_column(String(64), default="ACTIVE", nullable=False)
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    analysis_mode: Mapped[str] = mapped_column(String(32), default="AUTO", nullable=False)  # "AUTO" | "MANUAL"
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_cursor: Mapped[str | None] = mapped_column(String(256), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<GmailConnection id={self.id} workspace={self.workspace_id} email={self.email_address}>"
