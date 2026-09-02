"""
SentinelTrace Backend — AI Analysis and Agent Result ORM Models
"""
import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text, UniqueConstraint, Index
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.schemas.agent_result import AgentStatus, RiskVerdict
from app.models.email_analysis import ThreatCategory


class AIAnalysis(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_analyses"

    __table_args__ = (
        UniqueConstraint("workspace_id", "analysis_run_id", name="uq_ai_analysis_run"),
        Index("ix_ai_analysis_workspace_id", "workspace_id"),
        Index("ix_ai_analysis_email_id", "email_analysis_id"),
        Index("ix_ai_analysis_run_id", "analysis_run_id"),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    email_analysis_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("email_analyses.id", ondelete="CASCADE"), nullable=False)
    
    analysis_run_id: Mapped[str] = mapped_column(String, nullable=False)
    
    status: Mapped[str] = mapped_column(String, default="RUNNING", nullable=False)
    final_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    final_verdict: Mapped[RiskVerdict | None] = mapped_column(Enum(RiskVerdict, name="risk_verdict_enum"), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Store RiskFusion output details
    key_findings: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    evidence: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    contributing_agents: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    conflicting_agents: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    deterministic_indicators: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    workspace = relationship("Workspace")
    email_analysis = relationship("EmailAnalysis")
    agent_results = relationship("AgentResult", back_populates="ai_analysis", cascade="all, delete-orphan")


class AgentResult(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "agent_results"

    __table_args__ = (
        UniqueConstraint("workspace_id", "analysis_run_id", "agent_name", name="uq_agent_result_run_name"),
        Index("ix_agent_result_workspace_id", "workspace_id"),
        Index("ix_agent_result_analysis_run_id", "analysis_run_id"),
        Index("ix_agent_result_ai_analysis_id", "ai_analysis_id"),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    ai_analysis_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("ai_analyses.id", ondelete="CASCADE"), nullable=False)
    email_analysis_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("email_analyses.id", ondelete="CASCADE"), nullable=False)
    
    analysis_run_id: Mapped[str] = mapped_column(String, nullable=False)
    agent_name: Mapped[str] = mapped_column(String, nullable=False)
    agent_version: Mapped[str] = mapped_column(String, nullable=False)
    prompt_version: Mapped[str] = mapped_column(String, nullable=False)
    model: Mapped[str] = mapped_column(String, nullable=False)
    
    status: Mapped[AgentStatus] = mapped_column(Enum(AgentStatus, name="agent_status_enum"), nullable=False)
    
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    classification: Mapped[ThreatCategory | None] = mapped_column(Enum(ThreatCategory, name="threat_category_enum"), nullable=True)
    
    findings: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    evidence: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    recommendations: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    
    error_code: Mapped[str | None] = mapped_column(String, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Relationships
    ai_analysis = relationship("AIAnalysis", back_populates="agent_results")
