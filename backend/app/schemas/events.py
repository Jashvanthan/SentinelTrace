from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

class RealTimeEventType(str, Enum):
    ANALYSIS_STARTED = "ANALYSIS_STARTED"
    ANALYSIS_COMPLETED = "ANALYSIS_COMPLETED"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"
    EMAIL_RECEIVED = "EMAIL_RECEIVED"
    THREAT_DETECTED = "THREAT_DETECTED"
    IOC_CREATED = "IOC_CREATED"
    CAMPAIGN_UPDATED = "CAMPAIGN_UPDATED"


class RealTimeEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: RealTimeEventType
    workspace_id: uuid.UUID
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: str | None = None
    title: str
    message: str
    resource_type: str | None = None
    resource_id: str | None = None
