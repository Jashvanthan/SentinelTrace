"""
SentinelTrace Backend — Campaign Correlation API
"""
from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.core.deps import DbSession, require_workspace_role
from app.db.persistence import upsert_campaign, upsert_campaign_member
from app.models.campaign import Campaign, CampaignMember
from app.models.email_analysis import EmailAnalysis
from app.schemas.campaign import (
    CampaignCorrelationResponse,
    CampaignListResponse,
    CampaignMemberResponse,
    CampaignResponse,
)
from app.services.audit_service import write_audit_log
from app.services.campaign_correlation_service import CampaignCorrelationService

router = APIRouter(prefix="/workspaces/{workspace_id}/campaigns", tags=["campaigns"])


@router.post("/correlate/{email_analysis_id}", response_model=CampaignCorrelationResponse)
async def correlate_email(
    workspace_id: uuid.UUID,
    email_analysis_id: uuid.UUID,
    db: DbSession,
    member: Annotated[Any, Depends(require_workspace_role("owner", "admin", "analyst"))],
) -> CampaignCorrelationResponse:
    """
    Trigger campaign correlation for a specific email analysis.
    """
    # Verify email analysis belongs to the workspace
    email_analysis = await db.scalar(
        select(EmailAnalysis).where(
            EmailAnalysis.id == email_analysis_id,
            EmailAnalysis.workspace_id == workspace_id,
        )
    )
    if not email_analysis:
        await write_audit_log(
            db,
            action="CORRELATION_ATTEMPT_DENIED",
            user_id=member.user_id,
            resource_type="EmailAnalysis",
            resource_id=str(email_analysis_id),
            outcome="FAILURE",
            details={"workspace_id": str(workspace_id)},
        )
        await db.commit()
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Email analysis not found in this workspace")

    # Call the correlation service
    correlation_service = CampaignCorrelationService()
    evidence: dict[str, Any] = {}

    result = await correlation_service.correlate_email(
        workspace_id=str(workspace_id),
        email_analysis_id=str(email_analysis_id),
        evidence=evidence,
    )

    campaigns_affected: set[uuid.UUID] = set()

    if result.candidates:
        existing_campaign_id = None
        for candidate in result.candidates:
            if candidate.campaign_id:
                existing_campaign_id = uuid.UUID(candidate.campaign_id)
                break

        if not existing_campaign_id:
            existing_campaign_id = uuid.uuid4()
            campaign_data = {
                "id": existing_campaign_id,
                "workspace_id": workspace_id,
                "name": f"Automated Campaign {str(existing_campaign_id)[:8]}",
                "description": "Auto-correlated campaign",
                "status": "ACTIVE",
                "confidence": result.candidates[0].confidence,
                "correlation_score": result.candidates[0].correlation_score,
            }
            await upsert_campaign(db, campaign_data)

        campaigns_affected.add(existing_campaign_id)

        # Add target email to the campaign
        await upsert_campaign_member(
            db,
            {
                "workspace_id": workspace_id,
                "campaign_id": existing_campaign_id,
                "email_analysis_id": email_analysis_id,
                "correlation_score": result.candidates[0].correlation_score,
                "correlation_confidence": result.candidates[0].confidence,
                "matched_indicators": result.candidates[0].matched_indicator_types,
                "correlation_reasons": result.candidates[0].reasons,
            },
        )

        # Add matched candidates to the campaign
        for candidate in result.candidates:
            await upsert_campaign_member(
                db,
                {
                    "workspace_id": workspace_id,
                    "campaign_id": existing_campaign_id,
                    "email_analysis_id": uuid.UUID(candidate.email_analysis_id),
                    "correlation_score": candidate.correlation_score,
                    "correlation_confidence": candidate.confidence,
                    "matched_indicators": candidate.matched_indicator_types,
                    "correlation_reasons": candidate.reasons,
                },
            )

    await db.commit()

    await write_audit_log(
        db,
        action="CAMPAIGN_CORRELATION_TRIGGERED",
        user_id=member.user_id,
        resource_type="EmailAnalysis",
        resource_id=str(email_analysis_id),
        details={
            "campaigns_affected": [str(c) for c in campaigns_affected],
            "candidates_count": len(result.candidates),
        },
    )

    return CampaignCorrelationResponse(
        workspace_id=str(workspace_id),
        email_analysis_id=str(email_analysis_id),
        candidates=result.candidates,
        status=result.status,
        campaigns_affected=[str(c) for c in campaigns_affected],
    )


@router.get("", response_model=CampaignListResponse)
async def list_campaigns(
    workspace_id: uuid.UUID,
    db: DbSession,
    member: Annotated[Any, Depends(require_workspace_role("owner", "admin", "analyst"))],
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> CampaignListResponse:
    """
    List campaigns for the workspace.
    """
    total = await db.scalar(
        select(func.count(Campaign.id)).where(Campaign.workspace_id == workspace_id)
    )

    result = await db.execute(
        select(Campaign)
        .where(Campaign.workspace_id == workspace_id)
        .order_by(Campaign.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    campaigns = result.scalars().all()

    return CampaignListResponse(
        items=campaigns,
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/{campaign_id}", response_model=CampaignResponse)
async def get_campaign(
    workspace_id: uuid.UUID,
    campaign_id: uuid.UUID,
    db: DbSession,
    member: Annotated[Any, Depends(require_workspace_role("owner", "admin", "analyst", "viewer"))],
) -> CampaignResponse:
    """
    Get a specific campaign with members loaded.
    """
    campaign = await db.scalar(
        select(Campaign)
        .options(selectinload(Campaign.members))
        .where(
            Campaign.id == campaign_id,
            Campaign.workspace_id == workspace_id,
        )
    )

    if not campaign:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Campaign not found")

    return CampaignResponse.model_validate(campaign)



@router.get("/{campaign_id}/members", response_model=list[CampaignMemberResponse])
async def get_campaign_members(
    workspace_id: uuid.UUID,
    campaign_id: uuid.UUID,
    db: DbSession,
    member: Annotated[Any, Depends(require_workspace_role("owner", "admin", "analyst", "viewer"))],
) -> Any:
    """
    Get members of a specific campaign.
    """
    campaign = await db.scalar(
        select(Campaign).where(
            Campaign.id == campaign_id,
            Campaign.workspace_id == workspace_id,
        )
    )

    if not campaign:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Campaign not found")

    result = await db.execute(
        select(CampaignMember).where(
            CampaignMember.campaign_id == campaign_id,
            CampaignMember.workspace_id == workspace_id,
        )
    )

    return result.scalars().all()


@router.get("/{campaign_id}/timeline")
async def get_campaign_timeline(
    workspace_id: uuid.UUID,
    campaign_id: uuid.UUID,
    db: DbSession,
    member: Annotated[Any, Depends(require_workspace_role("owner", "admin", "analyst", "viewer"))],
) -> dict[str, Any]:
    """
    Get chronological UTC forensic investigation timeline for a campaign.
    """
    from app.services.forensic_timeline_service import ForensicTimelineService

    timeline = await ForensicTimelineService.build_campaign_timeline(
        db=db,
        workspace_id=workspace_id,
        campaign_id=campaign_id,
    )
    return {
        "campaign_id": str(campaign_id),
        "workspace_id": str(workspace_id),
        "timeline": timeline,
    }


@router.get("/{campaign_id}/graph")
async def get_campaign_graph_by_id(
    workspace_id: uuid.UUID,
    campaign_id: uuid.UUID,
    db: DbSession,
    member: Annotated[Any, Depends(require_workspace_role("owner", "admin", "analyst", "viewer"))],
    depth: int = Query(2, ge=1, le=5),
) -> dict[str, Any]:
    """
    Get multi-hop Neo4j campaign correlation graph.
    """
    from app.services.neo4j_service import get_neo4j_service

    neo4j = get_neo4j_service()
    graph = await neo4j.get_campaign_graph(
        workspace_id=str(workspace_id),
        campaign_id=str(campaign_id),
        depth=depth,
    )
    return graph
