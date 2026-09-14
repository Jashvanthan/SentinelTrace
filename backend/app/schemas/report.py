"""
SentinelTrace Backend — Forensic Report Pydantic Schemas
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.report import ReportStatus


class ReportCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = None


class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    workspace_id: uuid.UUID
    investigation_id: uuid.UUID
    title: str
    report_number: str
    version: int
    status: ReportStatus
    created_by_id: uuid.UUID
    created_at: datetime
    generated_at: datetime | None = None
    report_hash: str | None = None
    evidence_root_hash: str | None = None
    investigation_snapshot: dict[str, Any] = Field(default_factory=dict)
    limitations_snapshot: list[str] = Field(default_factory=list)


class ReportListResponse(BaseModel):
    items: list[ReportResponse]
    total: int
    limit: int
    offset: int
