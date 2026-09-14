"""
SentinelTrace Backend — Unified Forensic Investigation Search Router
"""
from __future__ import annotations

import re
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, or_, select

from app.core.deps import CurrentUser, DbSession, require_workspace_role
from app.models.campaign import Campaign
from app.models.email_analysis import EmailAnalysis
from app.models.ioc import IOC
from app.models.workspace import WorkspaceMember
from app.services.ioc_normalization_service import IOCNormalizationService
from app.services.ip_trace.service import IPTraceService

router = APIRouter(prefix="/investigation", tags=["Investigation Search"])
ip_trace_service = IPTraceService()


class SearchResultItem(BaseModel):
    model_config = ConfigDict(extra="ignore")

    entity_type: str
    id: str
    title: str
    subtitle: str | None = None
    threat_score: int | None = None
    severity: str | None = None
    workspace_id: str
    details: dict[str, Any] = {}


class UnifiedSearchResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    query: str
    workspace_id: str
    total_results: int
    results: list[SearchResultItem]
    ip_trace: dict[str, Any] | None = None


@router.get("/search", response_model=UnifiedSearchResponse)
async def unified_investigation_search(
    current_user: CurrentUser,
    db: DbSession,
    query: str = Query(..., min_length=1, description="Search term (IP, domain, URL, email, hash, campaign)"),
    workspace_id: uuid.UUID | None = Query(None),
):
    """
    Perform a unified, workspace-isolated investigation search across emails, IOCs, campaigns, and IP traces.
    """
    clean_query = query.strip()
    
    # Workspace resolution & authorization
    if not workspace_id:
        member = await db.scalar(
            select(WorkspaceMember).where(WorkspaceMember.user_id == current_user.id)
        )
        if member:
            workspace_id = member.workspace_id
        else:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")
    else:
        member = await db.scalar(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.user_id == current_user.id,
            )
        )
        if not member:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Access denied to workspace")

    results: list[SearchResultItem] = []

    # 1. Search Email Analyses
    email_stmt = (
        select(EmailAnalysis)
        .where(
            EmailAnalysis.workspace_id == workspace_id,
            or_(
                EmailAnalysis.subject.ilike(f"%{clean_query}%"),
                EmailAnalysis.sender.ilike(f"%{clean_query}%"),
                EmailAnalysis.recipient.ilike(f"%{clean_query}%"),
            ),
        )
        .limit(20)
    )
    emails = (await db.execute(email_stmt)).scalars().all()
    for e in emails:
        results.append(
            SearchResultItem(
                entity_type="EMAIL",
                id=str(e.id),
                title=e.subject or "Untitled Email Analysis",
                subtitle=f"Sender: {e.sender or 'Unknown'} | Date: {e.received_date or e.created_at}",
                threat_score=e.risk_score,
                severity=e.threat_category,
                workspace_id=str(workspace_id),
                details={
                    "analysis_id": str(e.id),
                    "sender": e.sender,
                    "recipient": e.recipient,
                    "verdict": e.verdict,
                },
            )
        )

    # 2. Search IOCs
    ioc_stmt = (
        select(IOC)
        .where(
            IOC.workspace_id == workspace_id,
            IOC.value.ilike(f"%{clean_query}%"),
        )
        .limit(25)
    )
    iocs = (await db.execute(ioc_stmt)).scalars().all()
    for i in iocs:
        results.append(
            SearchResultItem(
                entity_type="IOC",
                id=str(i.id),
                title=f"{i.ioc_type.value if hasattr(i.ioc_type, 'value') else i.ioc_type}: {i.value}",
                subtitle=f"Source: {i.source or 'Analysis Pipeline'} | Malicious: {bool(i.is_malicious)}",
                threat_score=i.threat_score,
                severity="HIGH" if i.is_malicious else "CLEAN",
                workspace_id=str(workspace_id),
                details={
                    "ioc_id": str(i.id),
                    "ioc_type": i.ioc_type.value if hasattr(i.ioc_type, "value") else i.ioc_type,
                    "value": i.value,
                    "analysis_id": str(i.analysis_id),
                },
            )
        )

    # 3. Search Campaigns
    campaign_stmt = (
        select(Campaign)
        .where(
            Campaign.workspace_id == workspace_id,
            or_(
                Campaign.name.ilike(f"%{clean_query}%"),
                Campaign.description.ilike(f"%{clean_query}%"),
            ),
        )
        .limit(10)
    )
    campaigns = (await db.execute(campaign_stmt)).scalars().all()
    for c in campaigns:
        results.append(
            SearchResultItem(
                entity_type="CAMPAIGN",
                id=str(c.id),
                title=c.name,
                subtitle=c.description or f"Status: {c.status}",
                threat_score=c.correlation_score,
                severity="CRITICAL" if (c.correlation_score or 0) >= 80 else "HIGH",
                workspace_id=str(workspace_id),
                details={
                    "campaign_id": str(c.id),
                    "status": c.status.value if hasattr(c.status, "value") else c.status,
                    "confidence": c.confidence,
                },
            )
        )

    # 4. If query is a valid IP, perform single IP Trace lookup
    ip_trace_data = None
    is_ipv4 = bool(re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", clean_query))
    is_ipv6 = ":" in clean_query and len(clean_query) >= 3

    if is_ipv4 or is_ipv6:
        try:
            ip_trace_data = await ip_trace_service.trace_ip(
                ip=clean_query,
                workspace_id=workspace_id,
                user_id=current_user.id,
            )
            results.insert(
                0,
                SearchResultItem(
                    entity_type="IP_TRACE",
                    id=clean_query,
                    title=f"IP Network Trace: {clean_query}",
                    subtitle=f"Classification: {ip_trace_data.get('classification')} | Location: {ip_trace_data.get('geo', {}).get('city') if ip_trace_data.get('geo') else 'N/A'}",
                    threat_score=ip_trace_data.get("threat", {}).get("score", 0),
                    severity=ip_trace_data.get("threat", {}).get("severity", "CLEAN"),
                    workspace_id=str(workspace_id),
                    details=ip_trace_data,
                ),
            )
        except Exception:
            pass

    return UnifiedSearchResponse(
        query=clean_query,
        workspace_id=str(workspace_id),
        total_results=len(results),
        results=results,
        ip_trace=ip_trace_data,
    )
