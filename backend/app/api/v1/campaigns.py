"""
SentinelTrace Backend — Campaign Correlation API
"""
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.deps import DbSession, require_workspace_role
from app.models.campaign import Campaign, CampaignMember
from app.models.email_analysis import EmailAnalysis
from app.schemas.campaign import CampaignListResponse, CampaignResponse, CampaignMemberResponse, CampaignCorrelationResponse
from app.services.audit_service import write_audit_log
from app.services.campaign_correlation_service import CampaignCorrelationService
from app.db.persistence import upsert_campaign, upsert_campaign_member

router = APIRouter(prefix="/workspaces/{workspace_id}/campaigns", tags=["campaigns"])


@router.post("/correlate/{email_analysis_id}", response_model=CampaignCorrelationResponse)
async def correlate_email(
    workspace_id: uuid.UUID,
    email_analysis_id: uuid.UUID,
    db: DbSession,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst"))],
):
    """
    Trigger campaign correlation for a specific email analysis.
    """
    # Verify email analysis belongs to the workspace
    email_analysis = await db.scalar(
        select(EmailAnalysis).where(
            EmailAnalysis.id == email_analysis_id,
            EmailAnalysis.workspace_id == workspace_id
        )
    )
    if not email_analysis:
        await write_audit_log(
            db, action="CORRELATION_ATTEMPT_DENIED", user_id=member.user_id,
            resource_type="EmailAnalysis", resource_id=str(email_analysis_id),
            outcome="FAILURE", details={"workspace_id": str(workspace_id)}
        )
        await db.commit()
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Email analysis not found in this workspace")

    # Call the correlation service
    correlation_service = CampaignCorrelationService()
    
    # In reality, evidence comes from AIAnalysis/EmailAnalysis records. For simplicity, we pass empty here as it's mocked in the service
    evidence = {}
    
    result = await correlation_service.correlate_email(
        workspace_id=str(workspace_id),
        email_analysis_id=str(email_analysis_id),
        evidence=evidence
    )

    campaigns_affected = set()

    # Persist the campaigns and campaign members based on candidates
    # A realistic logic: if candidates exist and have a campaign_id, we add this email to that campaign.
    # If candidates exist but have NO campaign_id, we create ONE new campaign and add all of them to it.
    
    # If no candidates, we do nothing and return empty.
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
                "correlation_score": result.candidates[0].correlation_score
            }
            await upsert_campaign(db, campaign_data)
            
        campaigns_affected.add(existing_campaign_id)
            
        # Add the target email to the campaign
        await upsert_campaign_member(db, {
            "workspace_id": workspace_id,
            "campaign_id": existing_campaign_id,
            "email_analysis_id": email_analysis_id,
            "correlation_score": result.candidates[0].correlation_score,
            "correlation_confidence": result.candidates[0].confidence,
            "matched_indicators": result.candidates[0].matched_indicator_types,
            "correlation_reasons": result.candidates[0].reasons
        })
        
        # Add matched candidates to the campaign
        for candidate in result.candidates:
            await upsert_campaign_member(db, {
                "workspace_id": workspace_id,
                "campaign_id": existing_campaign_id,
                "email_analysis_id": uuid.UUID(candidate.email_analysis_id),
                "correlation_score": candidate.correlation_score,
                "correlation_confidence": candidate.confidence,
                "matched_indicators": candidate.matched_indicator_types,
                "correlation_reasons": candidate.reasons
            })

    await db.commit()

    await write_audit_log(
        db, action="CAMPAIGN_CORRELATION_TRIGGERED", user_id=member.user_id,
        resource_type="EmailAnalysis", resource_id=str(email_analysis_id),
        details={"campaigns_affected": [str(c) for c in campaigns_affected], "candidates_count": len(result.candidates)}
    )

    return CampaignCorrelationResponse(
        workspace_id=str(workspace_id),
        email_analysis_id=str(email_analysis_id),
        candidates=result.candidates,
        status=result.status,
        campaigns_affected=list(campaigns_affected)
    )


@router.get("", response_model=CampaignListResponse)
async def list_campaigns(
    workspace_id: uuid.UUID,
    db: DbSession,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst"))],
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """
    List campaigns for the workspace.
    """
    # Count total
    total = await db.scalar(
        select(func.count(Campaign.id)).where(Campaign.workspace_id == workspace_id)
    )

    # Fetch paginated
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
        offset=offset
    )


@router.get("/{campaign_id}", response_model=CampaignResponse)
async def get_campaign(
    workspace_id: uuid.UUID,
    campaign_id: uuid.UUID,
    db: DbSession,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst", "viewer"))],
):
    """
    Get a specific campaign.
    """
    campaign = await db.scalar(
        select(Campaign)
        .options(selectinload(Campaign.members))
        .where(
            Campaign.id == campaign_id,
            Campaign.workspace_id == workspace_id
        )
    )

    if not campaign:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Campaign not found")

    return campaign


@router.get("/{campaign_id}/members", response_model=list[CampaignMemberResponse])
async def get_campaign_members(
    workspace_id: uuid.UUID,
    campaign_id: uuid.UUID,
    db: DbSession,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst", "viewer"))],
):
    """
    Get members of a specific campaign.
    """
    # Verify campaign belongs to workspace
    campaign = await db.scalar(
        select(Campaign).where(
            Campaign.id == campaign_id,
            Campaign.workspace_id == workspace_id
        )
    )

    if not campaign:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Campaign not found")

    # Fetch members
    result = await db.execute(
        select(CampaignMember)
        .where(
            CampaignMember.campaign_id == campaign_id,
            CampaignMember.workspace_id == workspace_id
        )
    )
    
    return result.scalars().all()
