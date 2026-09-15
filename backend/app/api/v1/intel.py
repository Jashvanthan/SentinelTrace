"""
SentinelTrace Backend — Threat Intelligence, Geo, Graph & Reports API
"""
from __future__ import annotations

import uuid
from sqlalchemy import select

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.core.deps import CurrentUser, DbSession, require_workspace_role
from app.models.workspace import WorkspaceMember
from typing import Annotated
from app.schemas.intel import (
    CampaignGraphResponse,
    EvidenceBundleResponse,
    EnrichmentRequest,
    EnrichmentResponse,
    GeoLocationRequest,
    GeoLocationResponse,
    ReportGenerateRequest,
    IOCListResponse,
    IOCResponse,
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
    providers = result.get("providers", {})
    vt = providers.get("virustotal")
    ab = providers.get("abuseipdb")
    sh = providers.get("shodan")

    return EnrichmentResponse(
        indicator=result["indicator"],
        indicator_type=result["indicator_type"],
        virustotal=vt if (vt and "error" not in vt) else None,
        abuseipdb=ab if (ab and "error" not in ab) else None,
        shodan=sh if (sh and "error" not in sh) else None,
        aggregate_threat_score=int(result.get("aggregate_threat_score", 0)),
        is_malicious=bool(result.get("is_malicious", False)),
        errors={k: v.get("error", "") for k, v in providers.items() if isinstance(v, dict) and "error" in v},
    )


@intel_router.get("", response_model=IOCListResponse)
@intel_router.get("/", response_model=IOCListResponse)
@intel_router.get("/indicators", response_model=IOCListResponse)
@intel_router.get("/iocs", response_model=IOCListResponse)
async def list_workspace_iocs(
    current_user: CurrentUser,
    db: DbSession,
    workspace_id: uuid.UUID | None = Query(None),
    search: str | None = Query(None),
    ioc_type: str | None = Query(None),
    is_malicious: bool | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
):
    from sqlalchemy import select, func, or_
    from app.models.ioc import IOC
    from app.models.email_analysis import EmailAnalysis
    from app.models.workspace import WorkspaceMember

    # Tenant isolation with safe auto-resolution
    if not workspace_id:
        member = await db.scalar(
            select(WorkspaceMember).where(WorkspaceMember.user_id == current_user.id)
        )
        if member:
            workspace_id = member.workspace_id
        if not member:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")
    else:
        member = await db.scalar(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.user_id == current_user.id,
            )
        )
        if not member:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")

    if not workspace_id:
        return IOCListResponse(items=[], total=0, page=page, page_size=page_size)

    stmt = (
        select(
            IOC,
            EmailAnalysis.subject,
            EmailAnalysis.sender_email,
            EmailAnalysis.threat_score,
            EmailAnalysis.confidence_score,
        )
        .join(
            EmailAnalysis,
            (IOC.analysis_id == EmailAnalysis.id) & (EmailAnalysis.workspace_id == workspace_id) & (EmailAnalysis.status == "COMPLETE"),
        )
        .where(IOC.workspace_id == workspace_id)
    )
    count_stmt = (
        select(func.count(IOC.id))
        .join(
            EmailAnalysis,
            (IOC.analysis_id == EmailAnalysis.id) & (EmailAnalysis.workspace_id == workspace_id) & (EmailAnalysis.status == "COMPLETE"),
        )
        .where(IOC.workspace_id == workspace_id)
    )

    if search and search.strip():
        search_term = f"%{search.strip()}%"
        search_filter = or_(
            IOC.value.ilike(search_term),
            EmailAnalysis.subject.ilike(search_term),
            EmailAnalysis.sender_email.ilike(search_term),
        )
        stmt = stmt.where(search_filter)
        count_stmt = count_stmt.where(search_filter)
    
    if ioc_type and ioc_type.strip():
        type_filter = IOC.ioc_type == ioc_type.strip()
        stmt = stmt.where(type_filter)
        count_stmt = count_stmt.where(type_filter)
        
    if is_malicious is not None:
        malicious_filter = IOC.is_malicious == is_malicious
        stmt = stmt.where(malicious_filter)
        count_stmt = count_stmt.where(malicious_filter)

    total = await db.scalar(count_stmt) or 0

    stmt = stmt.order_by(IOC.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(stmt)
    rows = result.all()

    TRUSTED_DOMAINS = (
        "github.com", "githubusercontent.com", "google.com", "gstatic.com",
        "microsoft.com", "azure.com", "live.com", "apple.com", "amazon.com",
        "aws.amazon.com", "linkedin.com", "twitter.com", "x.com", "gmail.com"
    )

    items = []
    for ioc, email_subject, sender_email, ea_threat_score, ea_conf_score in rows:
        val_lower = (ioc.value or "").lower()
        is_trusted_dom = any(dom in val_lower for dom in TRUSTED_DOMAINS)

        if is_trusted_dom and ioc.is_malicious is not True:
            resolved_is_malicious = False
            resolved_threat_score = 0
        elif ioc.threat_score is not None:
            resolved_threat_score = ioc.threat_score
            resolved_is_malicious = ioc.is_malicious
        elif ioc.is_malicious is False:
            resolved_threat_score = 0
            resolved_is_malicious = False
        elif ioc.is_malicious is True:
            resolved_threat_score = 85
            resolved_is_malicious = True
        else:
            resolved_threat_score = 0
            resolved_is_malicious = False

        resolved_conf_score = (
            ioc.confidence_score
            if ioc.confidence_score is not None
            else ea_conf_score
        )
        items.append(
            IOCResponse(
                id=str(ioc.id),
                analysis_id=str(ioc.analysis_id) if ioc.analysis_id else None,
                email_subject=email_subject,
                sender_email=sender_email,
                ioc_type=ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else str(ioc.ioc_type),
                value=ioc.value,
                is_malicious=resolved_is_malicious,
                confidence_score=resolved_conf_score,
                threat_score=resolved_threat_score,
                tags=ioc.tags,
                enrichment_data=ioc.enrichment_data,
                first_seen_at=ioc.first_seen_at,
                last_seen_at=ioc.last_seen_at,
                source=ioc.source,
                created_at=ioc.created_at.isoformat() if ioc.created_at else None,
            )
        )

    return IOCListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size
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
        is_hosting=result.get("is_hosting"),
        routing_type=result.get("routing_type"),
        routing_label=result.get("routing_label"),
        provider=result.get("provider", "unknown"),
    )


# ── Campaign Graph ────────────────────────────────────────────────────────────

async def _build_pg_campaign_graph(
    db: DbSession,
    workspace_id: uuid.UUID,
    campaign_id: str | None = None,
    analysis_id: uuid.UUID | None = None,
    depth: int = 2,
) -> dict:
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    from app.models.campaign import Campaign, CampaignMember
    from app.models.email_analysis import EmailAnalysis

    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    # 1. Fetch relevant campaign(s)
    campaigns = []
    if campaign_id:
        try:
            cid = uuid.UUID(campaign_id)
            c = await db.scalar(select(Campaign).where(Campaign.id == cid, Campaign.workspace_id == workspace_id))
            if c:
                campaigns.append(c)
        except ValueError:
            pass
    elif analysis_id:
        cm = await db.scalar(
            select(CampaignMember).where(
                CampaignMember.email_analysis_id == analysis_id,
                CampaignMember.workspace_id == workspace_id,
            )
        )
        if cm:
            c = await db.scalar(select(Campaign).where(Campaign.id == cm.campaign_id, Campaign.workspace_id == workspace_id))
            if c:
                campaigns.append(c)
    else:
        res = await db.execute(
            select(Campaign)
            .where(Campaign.workspace_id == workspace_id)
            .order_by(Campaign.created_at.desc())
            .limit(5)
        )
        campaigns = list(res.scalars().all())

    # Add Campaign nodes
    for camp in campaigns:
        cid_str = str(camp.id)
        nodes[f"camp-{cid_str}"] = {
            "id": f"camp-{cid_str}",
            "node_type": "Campaign",
            "label": camp.name,
            "properties": {
                "name": camp.name,
                "status": camp.status.value if hasattr(camp.status, "value") else str(camp.status),
                "confidence": camp.confidence,
                "score": camp.correlation_score,
            },
        }

    # 2. Fetch email analyses with IOCs and Attachments
    emails_to_fetch: set[uuid.UUID] = set()
    if analysis_id:
        emails_to_fetch.add(analysis_id)

    for camp in campaigns:
        m_res = await db.execute(
            select(CampaignMember).where(
                CampaignMember.campaign_id == camp.id,
                CampaignMember.workspace_id == workspace_id,
            )
        )
        for m in m_res.scalars().all():
            emails_to_fetch.add(m.email_analysis_id)

    base_query = (
        select(EmailAnalysis)
        .options(
            selectinload(EmailAnalysis.iocs),
            selectinload(EmailAnalysis.attachments),
        )
        .where(EmailAnalysis.workspace_id == workspace_id)
    )

    if not campaigns and not emails_to_fetch:
        e_res = await db.execute(base_query.order_by(EmailAnalysis.created_at.desc()).limit(15))
        email_list = list(e_res.scalars().all())
    elif emails_to_fetch:
        e_res = await db.execute(base_query.where(EmailAnalysis.id.in_(list(emails_to_fetch))))
        email_list = list(e_res.scalars().all())
    else:
        email_list = []

    for email in email_list:
        eid_str = str(email.id)
        label = (email.subject[:32] + "...") if email.subject and len(email.subject) > 32 else (email.subject or f"Email {eid_str[:8]}")
        
        # Safely determine verdict
        verdict_val = "BENIGN"
        if email.threat_category:
            verdict_val = email.threat_category.value if hasattr(email.threat_category, "value") else str(email.threat_category)
        elif email.severity:
            verdict_val = email.severity.value if hasattr(email.severity, "value") else str(email.severity)

        nodes[eid_str] = {
            "id": eid_str,
            "node_type": "Email",
            "label": label,
            "properties": {
                "subject": email.subject,
                "sender": email.sender_email,
                "verdict": verdict_val,
                "risk_score": email.threat_score,
            },
        }

        # Connect email to campaign(s)
        for camp in campaigns:
            edges.append({
                "source": eid_str,
                "target": f"camp-{str(camp.id)}",
                "relationship_type": "MEMBER_OF",
                "properties": {},
            })

        if depth < 2:
            continue

        # Sender node
        if email.sender_email:
            sender_id = f"sender-{email.sender_email}"
            if sender_id not in nodes:
                nodes[sender_id] = {
                    "id": sender_id,
                    "node_type": "Sender",
                    "label": email.sender_email,
                    "properties": {"email": email.sender_email},
                }
            edges.append({
                "source": eid_str,
                "target": sender_id,
                "relationship_type": "SENT_BY",
                "properties": {},
            })

            # Domain node
            if "@" in email.sender_email:
                domain = email.sender_email.split("@")[-1].lower()
                domain_id = f"domain-{domain}"
                if domain_id not in nodes:
                    nodes[domain_id] = {
                        "id": domain_id,
                        "node_type": "Domain",
                        "label": domain,
                        "properties": {"domain": domain},
                    }
                edges.append({
                    "source": sender_id,
                    "target": domain_id,
                    "relationship_type": "BELONGS_TO_DOMAIN",
                    "properties": {},
                })

        # Origin IP node from geo_data or indicators
        orig_ip = None
        if email.geo_data and isinstance(email.geo_data, dict):
            orig_ip = email.geo_data.get("ip_address") or email.geo_data.get("ip")
        if orig_ip:
            ip_id = f"ip-{orig_ip}"
            if ip_id not in nodes:
                nodes[ip_id] = {
                    "id": ip_id,
                    "node_type": "IPAddress",
                    "label": orig_ip,
                    "properties": {"ip": orig_ip},
                }
            edges.append({
                "source": eid_str,
                "target": ip_id,
                "relationship_type": "ORIGINATED_FROM",
                "properties": {},
            })

        if depth < 3:
            continue

        # IOC nodes
        for ioc in getattr(email, "iocs", []):
            ioc_id = f"ioc-{ioc.id}"
            if ioc_id not in nodes:
                nodes[ioc_id] = {
                    "id": ioc_id,
                    "node_type": "IOC",
                    "label": ioc.value[:30],
                    "properties": {
                        "value": ioc.value,
                        "type": ioc.ioc_type,
                        "malicious": ioc.is_malicious,
                    },
                }
            edges.append({
                "source": eid_str,
                "target": ioc_id,
                "relationship_type": "CONTAINS_IOC",
                "properties": {},
            })

        if depth < 4:
            continue

        # Attachment nodes
        for att in getattr(email, "attachments", []):
            att_id = f"att-{att.id}"
            if att_id not in nodes:
                nodes[att_id] = {
                    "id": att_id,
                    "node_type": "Attachment",
                    "label": att.filename or "attachment",
                    "properties": {
                        "filename": att.filename,
                        "size": att.size_bytes,
                        "sha256": att.sha256_hash,
                    },
                }
            edges.append({
                "source": eid_str,
                "target": att_id,
                "relationship_type": "HAS_ATTACHMENT",
                "properties": {},
            })

    email_count = len([n for n in nodes.values() if n["node_type"] == "Email"])
    return {
        "campaign_id": campaign_id,
        "nodes": list(nodes.values()),
        "edges": edges,
        "analysis_count": email_count,
    }


@graph_router.get("", response_model=CampaignGraphResponse)
@graph_router.get("/", response_model=CampaignGraphResponse)
@graph_router.get("/campaign", response_model=CampaignGraphResponse)
async def get_campaign_graph(
    current_user: CurrentUser,
    db: DbSession,
    workspace_id: uuid.UUID | None = Query(None),
    analysis_id: uuid.UUID | None = Query(None),
    campaign_id: str | None = Query(None),
    depth: int = Query(2, ge=1, le=4),
):
    """
    Return campaign correlation graph data for visualization.
    Provide either analysis_id or campaign_id.
    """
    from sqlalchemy import select
    from app.models.workspace import WorkspaceMember

    if not workspace_id:
        member = await db.scalar(
            select(WorkspaceMember).where(WorkspaceMember.user_id == current_user.id)
        )
        if member:
            workspace_id = member.workspace_id
    else:
        member = await db.scalar(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.user_id == current_user.id,
            )
        )
        if not member:
            # Fallback to user's first active workspace if current workspace_id is stale
            fallback_member = await db.scalar(
                select(WorkspaceMember).where(WorkspaceMember.user_id == current_user.id)
            )
            if fallback_member:
                workspace_id = fallback_member.workspace_id
            else:
                return CampaignGraphResponse(campaign_id=campaign_id, nodes=[], edges=[], analysis_count=0)

    if not workspace_id:
        return CampaignGraphResponse(campaign_id=campaign_id, nodes=[], edges=[], analysis_count=0)

    # 1. Try querying Neo4j
    graph = None
    try:
        neo4j = get_neo4j_service()
        raw_graph = await neo4j.get_campaign_graph(
            workspace_id=str(workspace_id),
            campaign_id=campaign_id,
            analysis_id=str(analysis_id) if analysis_id else None,
            depth=depth,
        )
        if raw_graph and len(raw_graph.get("nodes", [])) > 0:
            graph = raw_graph
    except Exception:
        graph = None

    # 2. Fall back to PostgreSQL relational data if Neo4j is offline or has no nodes
    if not graph:
        graph = await _build_pg_campaign_graph(
            db=db,
            workspace_id=workspace_id,
            campaign_id=campaign_id,
            analysis_id=analysis_id,
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
    from app.models.workspace import WorkspaceMember
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

    member = await db.scalar(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == analysis.workspace_id,
            WorkspaceMember.user_id == current_user.id,
        )
    )
    if not member:
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


@reports_router.get("/{analysis_id}/pdf")
async def get_report_pdf(
    analysis_id: uuid.UUID,
    current_user: CurrentUser,
    db: DbSession,
):
    """Download forensic evidence PDF report directly."""
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    from app.models.email_analysis import EmailAnalysis
    from app.models.workspace import WorkspaceMember
    from app.services.report_service import generate_pdf_report

    result = await db.execute(
        select(EmailAnalysis)
        .where(EmailAnalysis.id == analysis_id)
        .options(
            selectinload(EmailAnalysis.iocs),
            selectinload(EmailAnalysis.attachments),
            selectinload(EmailAnalysis.threat_records),
        )
    )
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")

    member = await db.scalar(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == analysis.workspace_id,
            WorkspaceMember.user_id == current_user.id,
        )
    )
    if not member:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")

    pdf_bytes = generate_pdf_report(analysis)
    filename = f"sentineltrace-report-{str(analysis_id)[:8]}.pdf"

    try:
        from app.services.audit_service import write_audit_log
        await write_audit_log(
            db,
            action="FORENSIC_REPORT_DOWNLOADED",
            user_id=current_user.id,
            resource_type="evidence_report",
            resource_id=str(analysis_id),
            details={"filename": filename, "subject": analysis.subject},
            outcome="SUCCESS",
        )
        await db.commit()
    except Exception:
        pass

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )


@reports_router.get("/{analysis_id}/download")
async def get_report_url(
    analysis_id: uuid.UUID,
    current_user: CurrentUser,
    db: DbSession,
):
    """Get download URL or direct PDF download link for the evidence report."""
    from app.models.email_analysis import EmailAnalysis
    from app.models.workspace import WorkspaceMember

    analysis = await db.get(EmailAnalysis, analysis_id)
    if not analysis:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")

    member = await db.scalar(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == analysis.workspace_id,
            WorkspaceMember.user_id == current_user.id,
        )
    )
    if not member:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")

    if analysis.report_gcs_path:
        gcs = GCSService()
        url = await gcs.generate_signed_url(analysis.report_gcs_path)
        if url:
            return {"download_url": url, "type": "signed_url"}

    return {
        "download_url": f"/api/v1/reports/{analysis_id}/pdf",
        "type": "direct_stream"
    }
