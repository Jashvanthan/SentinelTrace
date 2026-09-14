"""
SentinelTrace Backend — Pydantic Schemas: Email Analysis
"""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.email_analysis import AnalysisStatus, SeverityLevel, ThreatCategory


class EmailAnalysisCreateRequest(BaseModel):
    """Submitted when uploading a raw .eml file for analysis."""
    notes: str | None = Field(None, max_length=2048)
    priority: str = Field("NORMAL", pattern="^(LOW|NORMAL|HIGH|CRITICAL)$")


class IOCSchema(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    ioc_type: str
    value: str
    is_malicious: bool | None
    confidence_score: float | None
    threat_score: int | None
    tags: list[str] | None
    enrichment_data: dict | None
    source: str | None


class EmailAttachmentSchema(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    filename: str | None
    content_type: str | None
    size_bytes: int | None
    sha256_hash: str | None
    is_malicious: bool | None
    vt_detections: int | None
    vt_total_engines: int | None


class EmailAnalysisSummary(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    subject: str | None
    sender_email: str | None
    sender_domain: str | None
    status: AnalysisStatus
    threat_category: ThreatCategory | None
    severity: SeverityLevel | None
    confidence_score: float | None
    threat_score: float | None
    source_provider: str | None = None
    source_message_id: str | None = None
    created_at: datetime
    completed_at: datetime | None
    campaign_id: str | None


class EmailAnalysisDetail(EmailAnalysisSummary):
    sender_display_name: str | None
    reply_to: str | None
    recipients: list | None
    message_id: str | None
    email_date: datetime | None
    spf_result: str | None
    dkim_result: str | None
    dmarc_result: str | None
    received_headers: list | None
    ai_summary: str | None
    # Privacy Boundary: Internal model reasoning (chain-of-thought) is strictly non-user-facing
    ai_indicators: list | None
    enrichment_data: dict | None
    geo_data: dict | None
    diagnostic_status: dict | None = None
    raw_eml_sha256: str | None
    raw_eml_size_bytes: int | None
    iocs: list[IOCSchema] = []
    attachments: list[EmailAttachmentSchema] = []


class EmailAnalysisListResponse(BaseModel):
    items: list[EmailAnalysisSummary]
    total: int
    page: int
    page_size: int


class AnalysisTriggerResponse(BaseModel):
    analysis_id: uuid.UUID
    status: AnalysisStatus
    message: str


class ObservedIPItem(BaseModel):
    ip_address: str
    source: str  # "received_hop" | "origin_header" | "extracted_ioc"
    hop_number: int | None = None
    is_private: bool = False
    classification: str = "PUBLIC"  # PUBLIC, PRIVATE, LOOPBACK, LINK_LOCAL, MULTICAST, RESERVED, DOCUMENTATION
    description: str


class EmailObservedIPsResponse(BaseModel):
    analysis_id: uuid.UUID
    ips: list[ObservedIPItem]
    public_ips_count: int
    total_ips_count: int

