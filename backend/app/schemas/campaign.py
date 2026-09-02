"""
SentinelTrace Backend — Campaign Schemas
"""
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class CampaignMemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    workspace_id: UUID
    campaign_id: UUID
    email_analysis_id: UUID
    correlation_score: Optional[int] = None
    correlation_confidence: Optional[float] = None
    matched_indicators: List[str]
    correlation_reasons: List[str]
    created_at: datetime
    updated_at: datetime


class CampaignResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    workspace_id: UUID
    name: str
    description: Optional[str] = None
    status: str
    confidence: Optional[float] = None
    correlation_score: Optional[int] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    
    # Optional nested members if eager loaded
    members: Optional[List[CampaignMemberResponse]] = None


class CampaignListResponse(BaseModel):
    items: List[CampaignResponse]
    total: int
    limit: int
    offset: int


class CampaignCandidateResponse(BaseModel):
    email_analysis_id: str
    campaign_id: Optional[str] = None
    correlation_score: int
    confidence: float
    matched_indicator_types: List[str]
    reasons: List[str]


class CampaignCorrelationResponse(BaseModel):
    workspace_id: str
    email_analysis_id: str
    candidates: List[CampaignCandidateResponse]
    status: str
    campaigns_affected: List[UUID]
