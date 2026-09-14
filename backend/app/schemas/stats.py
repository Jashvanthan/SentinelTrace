"""
SentinelTrace Backend — Pydantic Schemas: Workspace Statistics

Returned by GET /api/v1/workspaces/{workspace_id}/stats

Notes:
- average_threat_score and workspace_risk_score are both derived from
  AVG(EmailAnalysis.threat_score) for the workspace.  They communicate
  different dashboard concepts (per-email average vs. overall workspace
  exposure level) but share the same underlying calculation for Step 14.
- high_critical_iocs_this_week is a derived proxy: IOC records whose
  threat_score >= 70 AND created_at falls within the current calendar week.
  The IOC model does not store an explicit severity field.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class CampaignSummary(BaseModel):
    """Lightweight campaign record for the dashboard top-campaigns widget."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    status: str
    confidence: Optional[float] = None
    correlation_score: Optional[int] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    member_count: int = Field(
        default=0,
        description="Number of email analyses correlated to this campaign.",
    )
    created_at: datetime
    updated_at: datetime


class RecentEmailSummary(BaseModel):
    """
    Minimal email analysis record surfaced in the dashboard live feed.

    Deliberately excludes raw_eml_gcs_path, OAuth tokens, API keys, and
    any other sensitive credential material.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    subject: Optional[str] = None
    sender_email: Optional[str] = None
    sender_domain: Optional[str] = None
    status: str
    threat_category: Optional[str] = None
    severity: Optional[str] = None
    threat_score: Optional[float] = None
    created_at: datetime
    completed_at: Optional[datetime] = None


class WorkspaceStatsResponse(BaseModel):
    """
    Aggregated workspace-level security statistics for the SOC dashboard.

    All counts are scoped exclusively to the requested workspace_id.

    Field notes
    -----------
    total_emails_scanned
        COUNT of all EmailAnalysis rows for the workspace.

    threats_detected
        COUNT of EmailAnalysis rows whose severity is CRITICAL, HIGH, or MEDIUM.

    active_campaigns
        COUNT of Campaign rows with status ACTIVE or MONITORING.

    average_threat_score
        AVG(EmailAnalysis.threat_score) for workspace rows where the score
        is not null.  Returns None for an empty workspace.

    workspace_risk_score
        Equal to average_threat_score for Step 14.  Kept as a separate field
        because future phases may weight it differently (e.g. by recency or
        campaign membership).

    high_critical_iocs_this_week
        COUNT of IOC rows with threat_score >= 70 created within the current
        calendar week (Monday 00:00 UTC → now).  Derived proxy — the IOC
        model does not store an explicit severity enum.

    ioc_type_distribution
        GROUP BY ioc_type count for all IOC rows in the workspace.
        E.g. {"IP_ADDRESS": 12, "DOMAIN": 8, "URL": 15, "FILE_HASH_SHA256": 6}

    top_campaigns
        Up to 3 most-recently-active campaigns for the workspace.

    recent_emails
        Up to 8 most-recently-created email analyses for the workspace.
    """

    total_emails_scanned: int = 0
    total_emails_fetched: int = 0
    total_emails_pending: int = 0
    threats_detected: int = 0
    active_campaigns: int = 0
    average_threat_score: Optional[float] = None
    workspace_risk_score: Optional[float] = None
    high_critical_iocs_this_week: int = 0
    ioc_type_distribution: dict[str, int] = Field(default_factory=dict)
    top_campaigns: list[CampaignSummary] = Field(default_factory=list)
    recent_emails: list[RecentEmailSummary] = Field(default_factory=list)
