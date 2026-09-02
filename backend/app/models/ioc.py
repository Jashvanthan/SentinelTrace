"""
SentinelTrace Backend — IOC (Indicator of Compromise) ORM Model
"""
from __future__ import annotations

import enum
import uuid

from sqlalchemy import Boolean, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class IOCType(str, enum.Enum):
    IP_ADDRESS = "IP_ADDRESS"
    DOMAIN = "DOMAIN"
    URL = "URL"
    EMAIL = "EMAIL"
    FILE_HASH_MD5 = "FILE_HASH_MD5"
    FILE_HASH_SHA256 = "FILE_HASH_SHA256"
    FILE_HASH_SHA1 = "FILE_HASH_SHA1"
    HEADER = "HEADER"
    USER_AGENT = "USER_AGENT"
    BITCOIN_ADDRESS = "BITCOIN_ADDRESS"
    CVE = "CVE"
    OTHER = "OTHER"


class IOC(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "iocs"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("email_analyses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ioc_type: Mapped[IOCType] = mapped_column(
        Enum(IOCType, name="ioc_type"),
        nullable=False,
        index=True,
    )
    value: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    is_malicious: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    threat_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tags: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    enrichment_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    first_seen_at: Mapped[str | None] = mapped_column(nullable=True)
    last_seen_at: Mapped[str | None] = mapped_column(nullable=True)
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)

    analysis: Mapped["EmailAnalysis"] = relationship(  # noqa: F821
        "EmailAnalysis", back_populates="iocs"
    )

    def __repr__(self) -> str:
        return f"<IOC id={self.id} type={self.ioc_type} value={self.value[:50]}>"
