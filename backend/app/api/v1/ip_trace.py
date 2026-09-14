"""
SentinelTrace Backend — IP Network Trace & Forensic Hop Chain API Router
"""
from __future__ import annotations

from typing import Annotated
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select

from app.core.deps import CurrentUser, DbSession, require_workspace_role
from app.core.logging import get_logger
from app.models.email_analysis import EmailAnalysis
from app.models.workspace import WorkspaceMember
from app.schemas.ip_trace import (
    EmailIPTraceResponse,
    IPTraceRequest,
    IPTraceResponse,
    ProvidersHealthResponse,
)
from app.services.audit_service import write_audit_log
from app.services.ip_trace.health import get_providers_health
from app.services.ip_trace.service import IPTraceService

router = APIRouter(prefix="/ip-trace", tags=["IP Network Trace"])
logger = get_logger("sentineltrace.api.ip_trace")

ip_trace_service = IPTraceService()


@router.get("/providers/health", response_model=ProvidersHealthResponse)
async def get_provider_health_status(
    current_user: CurrentUser,
):
    """
    Return operational readiness status of all IP Trace enrichment providers.
    Does not expose sensitive API credentials.
    """
    health = get_providers_health()
    return ProvidersHealthResponse.model_validate(health)



@router.post("/trace", response_model=IPTraceResponse)
async def trace_single_ip(
    payload: IPTraceRequest,
    current_user: CurrentUser,
    db: DbSession,
):
    """
    Perform deep forensic trace of a single IPv4 or IPv6 address.
    Strictly distinguishes Public from Private/LAN/Loopback/Link-local addresses.
    Secured with workspace isolation and audit logging.
    """
    target_workspace_id = payload.workspace_id

    # Validate workspace membership if workspace_id was passed
    if target_workspace_id:
        member = await db.scalar(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == target_workspace_id,
                WorkspaceMember.user_id == current_user.id,
            )
        )
        if not member:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")
    else:
        # Fallback to user's first active workspace
        member = await db.scalar(
            select(WorkspaceMember).where(WorkspaceMember.user_id == current_user.id)
        )
        if member:
            target_workspace_id = member.workspace_id

    trace_result = await ip_trace_service.trace_ip(
        ip=payload.ip,
        workspace_id=target_workspace_id,
        user_id=current_user.id,
    )

    # Record security audit log
    try:
        await write_audit_log(
            db=db,
            action="IP_NETWORK_TRACE_QUERY",
            user_id=current_user.id,
            resource_type="ip_trace",
            resource_id=trace_result.get("ip"),
            details={
                "ip": trace_result.get("ip"),
                "classification": trace_result.get("classification"),
                "workspace_id": str(target_workspace_id) if target_workspace_id else None,
            },
            outcome="SUCCESS",
        )
        await db.commit()
    except Exception as err:
        logger.debug("audit_log_trace_error", error=str(err))

    return IPTraceResponse.model_validate(trace_result)


@router.get("/analyses/{analysis_id}", response_model=EmailIPTraceResponse)
@router.get("/email/{analysis_id}", response_model=EmailIPTraceResponse)
async def trace_email_ip_hops(
    analysis_id: uuid.UUID,
    current_user: CurrentUser,
    db: DbSession,
    workspace_id: uuid.UUID | None = Query(None),
):
    """
    Construct full multi-hop transit graph, NAT boundary detection, and
    evidence ledger for an analyzed email.
    """
    # Enforce workspace authorization & isolation
    if workspace_id:
        member = await db.scalar(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.user_id == current_user.id,
            )
        )
        if not member:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found or workspace access denied")
        analysis = await db.scalar(
            select(EmailAnalysis).where(
                EmailAnalysis.id == analysis_id,
                EmailAnalysis.workspace_id == workspace_id,
            )
        )
    else:
        analysis = await db.get(EmailAnalysis, analysis_id)
        if analysis:
            member = await db.scalar(
                select(WorkspaceMember).where(
                    WorkspaceMember.workspace_id == analysis.workspace_id,
                    WorkspaceMember.user_id == current_user.id,
                )
            )
            if not member:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")

    if not analysis:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Email analysis not found")

    result = await ip_trace_service.trace_email_analysis(
        analysis=analysis,
        workspace_id=analysis.workspace_id,
        user_id=current_user.id,
    )

    return EmailIPTraceResponse.model_validate(result)
