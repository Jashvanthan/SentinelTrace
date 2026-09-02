"""
SentinelTrace Backend — Upsert Persistence Helpers
"""
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert
from app.models.ai_analysis import AIAnalysis, AgentResult
from app.models.campaign import Campaign, CampaignMember

logger = logging.getLogger(__name__)

async def upsert_ai_analysis(session: AsyncSession, analysis_data: dict) -> AIAnalysis:
    """
    Idempotent upsert for AIAnalysis.
    Resolves conflicts on (workspace_id, analysis_run_id).
    """
    stmt = insert(AIAnalysis).values(**analysis_data)
    update_dict = {
        c.name: c
        for c in stmt.excluded
        if c.name not in ["id", "workspace_id", "email_analysis_id", "analysis_run_id", "created_at"]
    }
    stmt = stmt.on_conflict_do_update(
        index_elements=["workspace_id", "analysis_run_id"],
        set_=update_dict
    ).returning(AIAnalysis)
    
    result = await session.execute(stmt)
    return result.scalars().first()

async def upsert_agent_result(session: AsyncSession, result_data: dict) -> AgentResult:
    """
    Idempotent upsert for AgentResult.
    Resolves conflicts on (workspace_id, analysis_run_id, agent_name).
    """
    stmt = insert(AgentResult).values(**result_data)
    update_dict = {
        c.name: c
        for c in stmt.excluded
        if c.name not in ["id", "workspace_id", "ai_analysis_id", "email_analysis_id", "analysis_run_id", "agent_name", "created_at"]
    }
    stmt = stmt.on_conflict_do_update(
        index_elements=["workspace_id", "analysis_run_id", "agent_name"],
        set_=update_dict
    ).returning(AgentResult)
    
    result = await session.execute(stmt)
    return result.scalars().first()


async def upsert_campaign(session: AsyncSession, campaign_data: dict) -> Campaign:
    """
    Idempotent upsert for Campaign.
    Resolves conflicts on (id). If a campaign is being created, an ID must be supplied.
    """
    if "id" not in campaign_data:
        import uuid
        campaign_data["id"] = uuid.uuid4()

    stmt = insert(Campaign).values(**campaign_data)
    update_dict = {
        c.name: c
        for c in stmt.excluded
        if c.name not in ["id", "workspace_id", "created_at"]
    }
    stmt = stmt.on_conflict_do_update(
        index_elements=["id"],
        set_=update_dict
    ).returning(Campaign)
    
    result = await session.execute(stmt)
    return result.scalars().first()


async def upsert_campaign_member(session: AsyncSession, member_data: dict) -> CampaignMember:
    """
    Idempotent upsert for CampaignMember.
    Resolves conflicts on (workspace_id, campaign_id, email_analysis_id).
    """
    if "id" not in member_data:
        import uuid
        member_data["id"] = uuid.uuid4()

    stmt = insert(CampaignMember).values(**member_data)
    update_dict = {
        c.name: c
        for c in stmt.excluded
        if c.name not in ["id", "workspace_id", "campaign_id", "email_analysis_id", "created_at"]
    }
    stmt = stmt.on_conflict_do_update(
        index_elements=["workspace_id", "campaign_id", "email_analysis_id"],
        set_=update_dict
    ).returning(CampaignMember)
    
    result = await session.execute(stmt)
    return result.scalars().first()
