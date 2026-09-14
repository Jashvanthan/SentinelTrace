"""
SentinelTrace Backend — Analyst Investigation Workspace Models
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Enum, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class InvestigationStatus(str, enum.Enum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    RESOLVED = "RESOLVED"
    ARCHIVED = "ARCHIVED"


class FindingSeverity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingConfidence(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class VerificationStatus(str, enum.Enum):
    UNREVIEWED = "UNREVIEWED"
    REVIEWED = "REVIEWED"
    VERIFIED = "VERIFIED"
    DISPUTED = "DISPUTED"


class Investigation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "investigations"

    __table_args__ = (
        Index("ix_investigation_workspace_id", "workspace_id"),
        Index("ix_investigation_workspace_status", "workspace_id", "status"),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[InvestigationStatus] = mapped_column(
        Enum(InvestigationStatus, name="investigation_status_enum"),
        default=InvestigationStatus.OPEN,
        nullable=False,
    )
    created_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)

    # Relationships
    workspace = relationship("Workspace")
    creator = relationship("User")
    entities = relationship("InvestigationEntity", back_populates="investigation", cascade="all, delete-orphan")
    notes = relationship("AnalystNote", back_populates="investigation", cascade="all, delete-orphan")
    findings = relationship("AnalystFinding", back_populates="investigation", cascade="all, delete-orphan")
    verifications = relationship("EvidenceVerification", back_populates="investigation", cascade="all, delete-orphan")


class InvestigationEntity(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "investigation_entities"

    __table_args__ = (
        UniqueConstraint("workspace_id", "investigation_id", "entity_type", "entity_id", name="uq_investigation_entity"),
        Index("ix_inv_entity_investigation", "investigation_id"),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False
    )
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)  # EMAIL, IOC, IP, DOMAIN, URL, HASH, CAMPAIGN
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False)
    entity_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    added_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    investigation = relationship("Investigation", back_populates="entities")


class AnalystNote(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "analyst_notes"

    __table_args__ = (
        Index("ix_analyst_note_investigation", "investigation_id"),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False
    )
    author_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)

    investigation = relationship("Investigation", back_populates="notes")
    author = relationship("User")


class AnalystFinding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "analyst_findings"

    __table_args__ = (
        Index("ix_analyst_finding_investigation", "investigation_id"),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, name="finding_severity_enum"),
        default=FindingSeverity.MEDIUM,
        nullable=False,
    )
    confidence: Mapped[FindingConfidence] = mapped_column(
        Enum(FindingConfidence, name="finding_confidence_enum"),
        default=FindingConfidence.HIGH,
        nullable=False,
    )
    evidence_references: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    created_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    investigation = relationship("Investigation", back_populates="findings")
    creator = relationship("User")


class EvidenceVerification(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "evidence_verifications"

    __table_args__ = (
        UniqueConstraint("workspace_id", "investigation_id", "evidence_id", name="uq_evidence_verification"),
        Index("ix_ev_verification_investigation", "investigation_id"),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False
    )
    evidence_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[VerificationStatus] = mapped_column(
        Enum(VerificationStatus, name="verification_status_enum"),
        default=VerificationStatus.UNREVIEWED,
        nullable=False,
    )
    verified_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    verified_at: Mapped[datetime] = mapped_column(nullable=False, default=lambda: datetime.now(timezone.utc))
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)

    investigation = relationship("Investigation", back_populates="verifications")
    verifier = relationship("User")
