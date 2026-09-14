"""
SentinelTrace Backend — Activity & Audit Log Schemas
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class ActivityLogItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    action: str
    resource_type: str | None = None
    resource_id: str | None = None
    user_id: uuid.UUID | None = None
    user_email: str | None = None
    user_name: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    outcome: str
    details: dict[str, Any] | None = None
    error_message: str | None = None
    created_at: datetime


class ActivityLogSummary(BaseModel):
    total_events: int
    success_count: int
    failure_count: int
    unique_users_count: int
    top_actions: dict[str, int]


class ActivityLogListResponse(BaseModel):
    items: list[ActivityLogItem]
    total: int
    page: int
    page_size: int
    summary: ActivityLogSummary
