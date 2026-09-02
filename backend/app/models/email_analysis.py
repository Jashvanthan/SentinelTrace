"""
SentinelTrace Backend — Email Analysis ORM Model
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AnalysisStatus(str, enum.Enum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    QUARANTINED = "QUARANTINED"


class ThreatCategory(str, enum.Enum):
    PHISHING = "PHISHING"
    SPEAR_PHISHING = "SPEAR_PHISHING"
    BEC = "BEC"              # Business Email Compromise
    MALWARE = "MALWARE"
    SPAM = "SPAM"
    RANSOMWARE = "RANSOMWARE"
    CREDENTIAL_HARVEST = "CREDENTIAL_HARVEST"
    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
    UNKNOWN = "UNKNOWN"
    BENIGN = "BENIGN"


class SeverityLevel(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EmailAnalysis(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "email_analyses"

    __table_args__ = (
        UniqueConstraint("workspace_id", "source_provider", "source_message_id", name="uq_workspace_source_msg"),
    )

    # ── Ownership ─────────────────────────────────────────────────────────────
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    analyst_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ── Email Metadata ────────────────────────────────────────────────────────
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    sender_email: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)
    sender_display_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    sender_domain: Mapped[str | None] = mapped_column(String(253), nullable=True, index=True)
    reply_to: Mapped[str | None] = mapped_column(Text, nullable=True)
    recipients: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    message_id: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    email_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # ── Ingestion Source ──────────────────────────────────────────────────────
    source_provider: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    source_message_id: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)

    # ── Raw Email Storage ────────────────────────────────────────────────────
    raw_eml_gcs_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_eml_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_eml_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ── Parsed Headers ───────────────────────────────────────────────────────
    received_headers: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    all_headers: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    authentication_results: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # ── Authentication Checks ────────────────────────────────────────────────
    spf_result: Mapped[str | None] = mapped_column(String(32), nullable=True)
    dkim_result: Mapped[str | None] = mapped_column(String(32), nullable=True)
    dmarc_result: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # ── Analysis Results ─────────────────────────────────────────────────────
    status: Mapped[AnalysisStatus] = mapped_column(
        Enum(AnalysisStatus, name="analysis_status"),
        default=AnalysisStatus.PENDING,
        nullable=False,
        index=True,
    )
    threat_category: Mapped[ThreatCategory | None] = mapped_column(
        Enum(ThreatCategory, name="threat_category"),
        nullable=True,
        index=True,
    )
    severity: Mapped[SeverityLevel | None] = mapped_column(
        Enum(SeverityLevel, name="severity_level"),
        nullable=True,
        index=True,
    )
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    threat_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # ── AI Analysis ──────────────────────────────────────────────────────────
    ai_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_indicators: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    ai_model_used: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # ── Enrichment ───────────────────────────────────────────────────────────
    enrichment_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    geo_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # ── Report ───────────────────────────────────────────────────────────────
    report_gcs_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Graph Correlation ─────────────────────────────────────────────────────
    campaign_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    # ── Relationships ─────────────────────────────────────────────────────────
    analyst: Mapped["User"] = relationship(  # noqa: F821
        "User", back_populates="email_analyses", foreign_keys=[analyst_id]
    )
    iocs: Mapped[list["IOC"]] = relationship(  # noqa: F821
        "IOC", back_populates="analysis", cascade="all, delete-orphan"
    )
    threat_records: Mapped[list["ThreatRecord"]] = relationship(  # noqa: F821
        "ThreatRecord", back_populates="analysis", cascade="all, delete-orphan"
    )
    attachments: Mapped[list["EmailAttachment"]] = relationship(  # noqa: F821
        "EmailAttachment", back_populates="analysis", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<EmailAnalysis id={self.id} status={self.status} severity={self.severity}>"


class EmailAttachment(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "email_attachments"

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
    filename: Mapped[str | None] = mapped_column(String(512), nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sha256_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    md5_hash: Mapped[str | None] = mapped_column(String(32), nullable=True)
    gcs_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_malicious: Mapped[bool | None] = mapped_column(nullable=True)
    vt_scan_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    vt_detections: Mapped[int | None] = mapped_column(Integer, nullable=True)
    vt_total_engines: Mapped[int | None] = mapped_column(Integer, nullable=True)

    analysis: Mapped[EmailAnalysis] = relationship("EmailAnalysis", back_populates="attachments")
