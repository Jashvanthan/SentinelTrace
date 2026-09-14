"""
SentinelTrace Backend — Forensic Report ORM Models
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Enum, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ReportStatus(str, enum.Enum):
    DRAFT = "DRAFT"
    GENERATING = "GENERATING"
    READY = "READY"
    FAILED = "FAILED"
    ARCHIVED = "ARCHIVED"


class ForensicReport(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "forensic_reports"

    __table_args__ = (
        Index("ix_forensic_report_workspace_id", "workspace_id"),
        Index("ix_forensic_report_investigation_id", "investigation_id"),
        Index("ix_forensic_report_workspace_inv", "workspace_id", "investigation_id"),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    report_number: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    status: Mapped[ReportStatus] = mapped_column(
        Enum(ReportStatus, name="report_status_enum"),
        default=ReportStatus.DRAFT,
        nullable=False,
    )
    created_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    generated_at: Mapped[datetime | None] = mapped_column(nullable=True)
    report_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)  # SHA-256
    evidence_root_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)  # SHA-256
    investigation_snapshot: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    limitations_snapshot: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    # Relationships
    workspace = relationship("Workspace")
    investigation = relationship("Investigation")
    creator = relationship("User")
