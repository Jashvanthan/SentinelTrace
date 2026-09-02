"""
SentinelTrace Backend — Threat Intelligence, Geo, Graph & Reports API
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Query, status

from app.core.deps import CurrentUser, DbSession
from app.schemas.intel import (
    CampaignGraphResponse,
    EvidenceBundleResponse,
    EnrichmentRequest,
    EnrichmentResponse,
    GeoLocationRequest,
    GeoLocationResponse,
    ReportGenerateRequest,
)
from app.services.geo_service import GeoService
from app.services.intel_service import ThreatIntelService
from app.services.neo4j_service import get_neo4j_service
from app.services.gcs_service import GCSService

intel_router = APIRouter(prefix="/intel", tags=["Threat Intelligence"])
geo_router = APIRouter(prefix="/geo", tags=["Geolocation"])
graph_router = APIRouter(prefix="/graph", tags=["Campaign Graph"])
reports_router = APIRouter(prefix="/reports", tags=["Reports & Evidence"])


# ── Threat Intelligence ───────────────────────────────────────────────────────

@intel_router.post("/enrich", response_model=EnrichmentResponse)
async def enrich_indicator(
    payload: EnrichmentRequest,
    current_user: CurrentUser,
):
    """
    Enrich an IOC against configured threat intelligence providers.
    Supports: IP addresses, domains, URLs, file hashes.
    """
    service = ThreatIntelService()
    result = await service.enrich(
        payload.indicator,
        payload.indicator_type,
        payload.providers,
    )
    return EnrichmentResponse(
        indicator=result["indicator"],
        indicator_type=result["indicator_type"],
        virustotal=result.get("providers", {}).get("virustotal"),
        abuseipdb=result.get("providers", {}).get("abuseipdb"),
        shodan=result.get("providers", {}).get("shodan"),
        aggregate_threat_score=result["aggregate_threat_score"],
        is_malicious=result["is_malicious"],
        errors={k: v.get("error", "") for k, v in result.get("providers", {}).items() if "error" in v},
    )


# ── Geolocation ───────────────────────────────────────────────────────────────

@geo_router.post("/locate", response_model=GeoLocationResponse)
async def geolocate_ip(payload: GeoLocationRequest, current_user: CurrentUser):
    """Geolocate an IP address using configured geolocation providers."""
    service = GeoService()
    result = await service.geolocate(payload.ip_address)
    return GeoLocationResponse(
        ip_address=result.get("ip_address", payload.ip_address),
        country=result.get("country"),
        country_code=result.get("country_code"),
        region=result.get("region"),
        city=result.get("city"),
        postal=result.get("postal"),
        latitude=result.get("latitude"),
        longitude=result.get("longitude"),
        timezone=result.get("timezone"),
        isp=result.get("isp"),
        org=result.get("org"),
        asn=result.get("asn"),
        is_proxy=result.get("is_proxy"),
        is_vpn=result.get("is_vpn"),
        is_tor=result.get("is_tor"),
        provider=result.get("provider", "unknown"),
    )


# ── Campaign Graph ────────────────────────────────────────────────────────────

@graph_router.get("/campaign", response_model=CampaignGraphResponse)
async def get_campaign_graph(
    current_user: CurrentUser,
    analysis_id: uuid.UUID | None = Query(None),
    campaign_id: str | None = Query(None),
    depth: int = Query(2, ge=1, le=4),
):
    """
    Return campaign correlation graph data for visualization.
    Provide either analysis_id or campaign_id.
    """
    neo4j = get_neo4j_service()
    graph = await neo4j.get_campaign_graph(
        campaign_id=campaign_id,
        analysis_id=str(analysis_id) if analysis_id else None,
        depth=depth,
    )
    return CampaignGraphResponse(**graph)


# ── Reports ───────────────────────────────────────────────────────────────────

@reports_router.post("/generate")
async def generate_report(
    payload: ReportGenerateRequest,
    current_user: CurrentUser,
    db: DbSession,
):
    """Generate and upload a forensic evidence report to GCS."""
    from app.models.email_analysis import EmailAnalysis
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    analysis_uuid = uuid.UUID(payload.analysis_id)
    result = await db.execute(
        select(EmailAnalysis)
        .where(EmailAnalysis.id == analysis_uuid)
        .options(
            selectinload(EmailAnalysis.iocs),
            selectinload(EmailAnalysis.attachments),
            selectinload(EmailAnalysis.threat_records),
        )
    )
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")

    # Simple evidence bundle response (PDF generation requires reportlab)
    gcs = GCSService()
    signed_url = None
    if analysis.report_gcs_path:
        signed_url = await gcs.generate_signed_url(analysis.report_gcs_path)

    from datetime import UTC, datetime, timedelta
    return EvidenceBundleResponse(
        analysis_id=payload.analysis_id,
        sha256_hash=analysis.raw_eml_sha256 or "",
        gcs_path=analysis.report_gcs_path or "",
        signed_url=signed_url or "",
        signed_url_expires_at=(
            datetime.now(UTC) + timedelta(minutes=60)
        ).isoformat(),
        chain_of_custody=[
            {
                "action": "EMAIL_INGESTED",
                "actor": str(analysis.analyst_id),
                "timestamp": analysis.created_at.isoformat(),
            },
            {
                "action": "ANALYSIS_COMPLETE",
                "actor": "system",
                "timestamp": analysis.completed_at.isoformat() if analysis.completed_at else "",
            },
        ],
    )


@reports_router.get("/{analysis_id}/download")
async def get_report_url(
    analysis_id: uuid.UUID,
    current_user: CurrentUser,
    db: DbSession,
):
    """Get a signed URL to download the evidence report."""
    from app.models.email_analysis import EmailAnalysis

    analysis = await db.get(EmailAnalysis, analysis_id)
    if not analysis:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")
    if not analysis.report_gcs_path:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No report generated yet")

    gcs = GCSService()
    url = await gcs.generate_signed_url(analysis.report_gcs_path)
    if not url:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "GCS not configured")

    return {"signed_url": url}
