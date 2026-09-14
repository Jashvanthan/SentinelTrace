"""
SentinelTrace Backend — IP Trace Pydantic Schemas
"""
from __future__ import annotations

from typing import Any
import uuid

from pydantic import BaseModel, Field


class IPTraceRequest(BaseModel):
    ip: str = Field(..., description="IPv4 or IPv6 address to trace")
    workspace_id: uuid.UUID | None = Field(None, description="Active workspace ID")


class GeoInfo(BaseModel):
    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    postal: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    accuracy: str = "approximate"
    accuracy_radius: float | None = None
    timezone: str | None = None
    continent: str | None = None
    provider: str | None = None


class NetworkInfo(BaseModel):
    asn: str | None = None
    organization: str | None = None
    isp: str | None = None
    cidr: str | None = None
    routing_type: str = "DIRECT_ENTERPRISE"
    routing_label: str = "Direct Public Routing"
    is_hosting: bool = False
    is_vpn: bool = False
    is_tor: bool = False
    is_proxy: bool = False


class DNSInfo(BaseModel):
    reverse_dns: str | None = None
    status: str | None = None


class ThreatInfo(BaseModel):
    score: int = 0
    severity: str = "CLEAN"
    status: str = "CLEAN"
    is_malicious: bool = False
    provider_coverage: str | None = None
    score_explanation: list[dict[str, Any]] = Field(default_factory=list)
    provider_disagreement_detected: bool = False
    disagreement_details: list[str] | None = None
    virustotal: dict[str, Any] | None = None
    abuseipdb: dict[str, Any] | None = None
    shodan: dict[str, Any] | None = None



class InternalNetworkInfo(BaseModel):
    mac: str | None = None
    hostname: str | None = None
    vlan: str | int | None = None
    switch: str | None = None
    port: str | None = None
    access_point: str | None = None
    ssid: str | None = None
    physical_location: dict[str, Any] | None = None  # building, floor, room
    location_confidence: str = "UNKNOWN"
    reason: str | None = None


class EvidenceItem(BaseModel):
    source_type: str
    source: str
    timestamp: str
    value: str
    confidence: str = "HIGH"
    hop_number: int | None = None


class IPTraceResponse(BaseModel):
    ip: str
    version: int = 4
    classification: str
    is_public: bool
    is_private: bool
    is_geolocatable: bool
    routing_role: str = "Public Internet Node"
    geo: GeoInfo | None = None
    network: NetworkInfo | None = None
    dns: DNSInfo | None = None
    threat: ThreatInfo | None = None
    internal_network: InternalNetworkInfo | None = None
    status: str = "RESOLVED"
    location_accuracy: str = "approximate"
    retrieved_at: str | None = None
    evidence: list[EvidenceItem] = Field(default_factory=list)


class EmailHopNode(BaseModel):
    hop_number: int
    ip: str | None = None
    classification: str
    is_public: bool = False
    is_private: bool = True
    network_role: str
    trust_level: str = "UNKNOWN"
    trust_reason: str | None = None
    hostname: str | None = None
    by_host: str | None = None
    timestamp: str | None = None
    header_name: str | None = None
    raw_header: str | None = None
    trace_details: IPTraceResponse | None = None


class EmailTimelineItem(BaseModel):
    step: int
    timestamp: str
    ip: str
    classification: str
    role: str
    hostname: str | None = None
    trust_level: str = "UNKNOWN"
    header_source: str | None = None
    geo_summary: str | None = None


class EmailPublicLocation(BaseModel):
    hop_number: int
    ip: str
    latitude: float
    longitude: float
    city: str | None = None
    country: str | None = None
    country_code: str | None = None
    asn: str | None = None
    isp: str | None = None
    threat_score: int = 0
    threat_status: str = "CLEAN"
    role: str


class EmailPrivateNode(BaseModel):
    hop_number: int
    ip: str
    classification: str
    hostname: str | None = None
    mac: str | None = None
    vlan: str | int | None = None
    switch: str | None = None
    port: str | None = None
    access_point: str | None = None
    physical_location: dict[str, Any] | None = None
    role: str
    status: str = "unavailable"


class EmailBoundary(BaseModel):
    boundary_type: str
    label: str
    from_hop: int
    to_hop: int
    ip: str | None = None
    description: str


class EmailIPTraceResponse(BaseModel):
    analysis_id: str
    total_hops: int
    hops: list[EmailHopNode] = Field(default_factory=list)
    timeline: list[EmailTimelineItem] = Field(default_factory=list)
    public_locations: list[EmailPublicLocation] = Field(default_factory=list)
    private_network_nodes: list[EmailPrivateNode] = Field(default_factory=list)
    boundaries: list[EmailBoundary] = Field(default_factory=list)
    has_nat_boundary: bool = False
    evidence: list[EvidenceItem] = Field(default_factory=list)


class ProviderStatusItem(BaseModel):
    configured: bool
    available: bool
    provider: str | None = None
    mode: str | None = None
    status: str | None = None
    reason: str | None = None
    accuracy: str | None = None


class ProvidersHealthResponse(BaseModel):
    geoip: ProviderStatusItem
    asn: ProviderStatusItem
    reverse_dns: ProviderStatusItem
    virustotal: ProviderStatusItem
    abuseipdb: ProviderStatusItem
    shodan: ProviderStatusItem
    internal_telemetry: ProviderStatusItem
