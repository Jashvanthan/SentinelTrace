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
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    total_engines: int = 0
    threat_names: list[str] = []
    last_analysis_date: int | str | None = None
    reputation: int | None = None


class AbuseIPDBResult(BaseModel):
    ip_address: str = ""
    abuse_confidence_score: int = 0
    total_reports: int = 0
    country_code: str | None = None
    isp: str | None = None
    domain: str | None = None
    is_whitelisted: bool = False


class ShodanResult(BaseModel):
    ip_str: str = ""
    ports: list[int] = []
    hostnames: list[str] = []
    country_name: str | None = None
    city: str | None = None
    org: str | None = None
    isp: str | None = None
    os: str | None = None
    vulns: list[str] = []
    last_update: str | None = None


class EnrichmentResponse(BaseModel):
    indicator: str
    indicator_type: str
    virustotal: VirusTotalResult | dict | None = None
    abuseipdb: AbuseIPDBResult | dict | None = None
    shodan: ShodanResult | dict | None = None
    aggregate_threat_score: int = 0
    is_malicious: bool = False
    errors: dict[str, str] = {}


class IOCResponse(BaseModel):
    id: str
    analysis_id: str | None = None
    email_subject: str | None = None
    sender_email: str | None = None
    ioc_type: str
    value: str
    is_malicious: bool | None = None
    confidence_score: float | None = None
    threat_score: int | None = None
    tags: list[str] | None = None
    enrichment_data: dict | None = None
    first_seen_at: str | None = None
    last_seen_at: str | None = None
    source: str | None = None
    created_at: str | None = None


class IOCListResponse(BaseModel):
    items: list[IOCResponse]
    total: int
    page: int
    page_size: int


import ipaddress
from pydantic import BaseModel, Field, field_validator


# ── Geolocation ───────────────────────────────────────────────────────────────

class GeoLocationRequest(BaseModel):
    ip_address: str = Field(..., min_length=1, max_length=64, description="IPv4 or IPv6 address to geolocate")

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        clean = v.strip()
        parts = clean.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            try:
                clean = ".".join(str(int(p)) for p in parts)
            except ValueError:
                pass
        try:
            ip_obj = ipaddress.ip_address(clean)
            return str(ip_obj)
        except ValueError:
            raise ValueError(f"Invalid IP address format: '{v.strip()}'. Must be a valid IPv4 or IPv6 address.")


class GeoLocationResponse(BaseModel):
    ip_address: str
    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    postal: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    accuracy_radius: int | float | None = None
    timezone: str | None = None
    continent: str | None = None
    network: str | None = None
    isp: str | None = None
    org: str | None = None
    asn: str | None = None
    is_proxy: bool | None = None
    is_vpn: bool | None = None
    is_tor: bool | None = None
    is_hosting: bool | None = None
    routing_type: str | None = None
    routing_label: str | None = None
    provider: str
    location_status: str | None = "RESOLVED"
    location_confidence: str | None = "HIGH_CONFIDENCE"
    provider_comparison: list[dict] | None = None



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
    campaign_id: str | None = None
    nodes: list[CampaignNodeSchema] = []
    edges: list[CampaignEdgeSchema] = []
    analysis_count: int = 0


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
