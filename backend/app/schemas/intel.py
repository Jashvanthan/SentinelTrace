"""
SentinelTrace Backend — Pydantic Schemas: Threat Intelligence & Geolocation
"""
from __future__ import annotations

from pydantic import BaseModel, Field


# ── Threat Intelligence ───────────────────────────────────────────────────────

class EnrichmentRequest(BaseModel):
    indicator: str = Field(..., min_length=1, max_length=512)
    indicator_type: str = Field(..., pattern="^(ip|domain|url|hash|email)$")
    providers: list[str] = Field(
        default=["virustotal", "abuseipdb", "shodan"],
        description="Which providers to query",
    )


class VirusTotalResult(BaseModel):
    malicious_count: int
    suspicious_count: int
    harmless_count: int
    total_engines: int
    threat_names: list[str]
    last_analysis_date: str | None
    reputation: int | None


class AbuseIPDBResult(BaseModel):
    ip_address: str
    abuse_confidence_score: int
    total_reports: int
    country_code: str | None
    isp: str | None
    domain: str | None
    is_whitelisted: bool


class ShodanResult(BaseModel):
    ip_str: str
    ports: list[int]
    hostnames: list[str]
    country_name: str | None
    city: str | None
    org: str | None
    isp: str | None
    os: str | None
    vulns: list[str]
    last_update: str | None


class EnrichmentResponse(BaseModel):
    indicator: str
    indicator_type: str
    virustotal: VirusTotalResult | None = None
    abuseipdb: AbuseIPDBResult | None = None
    shodan: ShodanResult | None = None
    aggregate_threat_score: int
    is_malicious: bool
    errors: dict[str, str] = {}


# ── Geolocation ───────────────────────────────────────────────────────────────

class GeoLocationRequest(BaseModel):
    ip_address: str


class GeoLocationResponse(BaseModel):
    ip_address: str
    country: str | None
    country_code: str | None
    region: str | None
    city: str | None
    postal: str | None
    latitude: float | None
    longitude: float | None
    timezone: str | None
    isp: str | None
    org: str | None
    asn: str | None
    is_proxy: bool | None
    is_vpn: bool | None
    is_tor: bool | None
    provider: str


# ── Campaign Graph ────────────────────────────────────────────────────────────

class CampaignNodeSchema(BaseModel):
    id: str
    node_type: str
    label: str
    properties: dict


class CampaignEdgeSchema(BaseModel):
    source: str
    target: str
    relationship_type: str
    properties: dict


class CampaignGraphResponse(BaseModel):
    campaign_id: str | None
    nodes: list[CampaignNodeSchema]
    edges: list[CampaignEdgeSchema]
    analysis_count: int


# ── Evidence / Reports ────────────────────────────────────────────────────────

class EvidenceBundleResponse(BaseModel):
    analysis_id: str
    sha256_hash: str
    gcs_path: str
    signed_url: str
    signed_url_expires_at: str
    chain_of_custody: list[dict]


class ReportGenerateRequest(BaseModel):
    analysis_id: str
    include_raw_headers: bool = True
    include_geo_map: bool = True
    include_ioc_table: bool = True
    include_ai_summary: bool = True
    format: str = Field("pdf", pattern="^(pdf|json)$")
