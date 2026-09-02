"""
SentinelTrace Backend — Threat Record ORM Model

Stores enriched threat intelligence records associated with an email analysis.
"""
from __future__ import annotations

import enum
import uuid

from sqlalchemy import Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ThreatProvider(str, enum.Enum):
    VIRUSTOTAL = "VIRUSTOTAL"
    ABUSEIPDB = "ABUSEIPDB"
    SHODAN = "SHODAN"
    INTERNAL = "INTERNAL"
    MCP_TOOL = "MCP_TOOL"
    AI_CLASSIFIER = "AI_CLASSIFIER"


class ThreatRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "threat_records"

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
    provider: Mapped[ThreatProvider] = mapped_column(
        Enum(ThreatProvider, name="threat_provider"),
        nullable=False,
    )
    indicator: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    indicator_type: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_response: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    threat_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    malicious_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_engines: Mapped[int | None] = mapped_column(Integer, nullable=True)
    categories: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    asn: Mapped[str | None] = mapped_column(String(32), nullable=True)
    isp: Mapped[str | None] = mapped_column(String(256), nullable=True)
    geo_lat: Mapped[float | None] = mapped_column(Float, nullable=True)
    geo_lon: Mapped[float | None] = mapped_column(Float, nullable=True)
    geo_city: Mapped[str | None] = mapped_column(String(128), nullable=True)
    geo_region: Mapped[str | None] = mapped_column(String(128), nullable=True)

    analysis: Mapped["EmailAnalysis"] = relationship(  # noqa: F821
        "EmailAnalysis", back_populates="threat_records"
    )

    def __repr__(self) -> str:
        return f"<ThreatRecord id={self.id} provider={self.provider} score={self.threat_score}>"
