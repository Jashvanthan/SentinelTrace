"""
SentinelTrace Backend — Campaign and Correlation Models
"""
import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text, UniqueConstraint, Index
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class CampaignStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    MONITORING = "MONITORING"
    MITIGATED = "MITIGATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CLOSED = "CLOSED"


class Campaign(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "campaigns"

    __table_args__ = (
        Index("ix_campaign_workspace_id", "workspace_id"),
        Index("ix_campaign_workspace_status", "workspace_id", "status"),
        Index("ix_campaign_workspace_last_seen", "workspace_id", "last_seen_at"),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    status: Mapped[CampaignStatus] = mapped_column(Enum(CampaignStatus, name="campaign_status_enum"), default=CampaignStatus.ACTIVE, nullable=False)
    
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    correlation_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    workspace = relationship("Workspace")
    members = relationship("CampaignMember", back_populates="campaign", cascade="all, delete-orphan")


class CampaignMember(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "campaign_members"

    __table_args__ = (
        UniqueConstraint("workspace_id", "campaign_id", "email_analysis_id", name="uq_campaign_member"),
        Index("ix_campaign_member_workspace_id", "workspace_id"),
        Index("ix_campaign_member_campaign_id", "campaign_id"),
        Index("ix_campaign_member_email_id", "email_analysis_id"),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    campaign_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False)
    email_analysis_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("email_analyses.id", ondelete="CASCADE"), nullable=False)
    
    correlation_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    correlation_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    
    matched_indicators: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    correlation_reasons: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    
    # Relationships
    campaign = relationship("Campaign", back_populates="members")
    email_analysis = relationship("EmailAnalysis")
