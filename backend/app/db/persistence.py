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
