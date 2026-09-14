"""
SentinelTrace Backend — Analyst Investigation Workspace Pydantic Schemas
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.investigation import FindingConfidence, FindingSeverity, InvestigationStatus, VerificationStatus


class InvestigationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    starting_entity_type: str | None = None  # EMAIL, IOC, IP, DOMAIN, URL, HASH, CAMPAIGN
    starting_entity_id: str | None = None
    starting_entity_value: str | None = None


class InvestigationUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    description: str | None = None
    status: InvestigationStatus | None = None


class EntityAttachRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: str  # EMAIL, IOC, IP, DOMAIN, URL, HASH, CAMPAIGN
    entity_id: str
    entity_value: str | None = None


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(..., min_length=1)


class FindingCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=255)
    description: str = Field(..., min_length=1)
    severity: FindingSeverity = FindingSeverity.MEDIUM
    confidence: FindingConfidence = FindingConfidence.HIGH
    evidence_references: list[str] = Field(default_factory=list)


class EvidenceVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: VerificationStatus
    comment: str | None = None


class InvestigationEntityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    investigation_id: uuid.UUID
    workspace_id: uuid.UUID
    entity_type: str
    entity_id: str
    entity_value: str | None = None
    added_by_id: uuid.UUID
    created_at: datetime


class AnalystNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    investigation_id: uuid.UUID
    workspace_id: uuid.UUID
    author_id: uuid.UUID
    content: str
    created_at: datetime
    updated_at: datetime


class AnalystFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    investigation_id: uuid.UUID
    workspace_id: uuid.UUID
    title: str
    description: str
    severity: FindingSeverity
    confidence: FindingConfidence
    evidence_references: list[str] = Field(default_factory=list)
    created_by_id: uuid.UUID
    created_at: datetime


class EvidenceVerificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    investigation_id: uuid.UUID
    workspace_id: uuid.UUID
    evidence_id: str
    status: VerificationStatus
    verified_by_id: uuid.UUID
    verified_at: datetime
    comment: str | None = None


class InvestigationRiskSummary(BaseModel):
    risk_score: int
    severity: str
    evidence_count: int
    entity_count: int
    finding_count: int
    high_risk_entities: list[str] = Field(default_factory=list)
    contributors: list[dict[str, Any]] = Field(default_factory=list)


class InvestigationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    workspace_id: uuid.UUID
    name: str
    description: str | None = None
    status: InvestigationStatus
    created_by_id: uuid.UUID
    risk_score: int | None = 0
    created_at: datetime
    updated_at: datetime
    entities: list[InvestigationEntityResponse] = Field(default_factory=list)
    notes: list[AnalystNoteResponse] = Field(default_factory=list)
    findings: list[AnalystFindingResponse] = Field(default_factory=list)
    verifications: list[EvidenceVerificationResponse] = Field(default_factory=list)
    risk_summary: InvestigationRiskSummary | None = None


class InvestigationListResponse(BaseModel):
    items: list[InvestigationResponse]
    total: int
    limit: int
    offset: int
