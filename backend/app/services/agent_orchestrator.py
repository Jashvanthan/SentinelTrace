"""
SentinelTrace Backend — Agent Orchestrator
"""
import asyncio
import logging
import uuid
import json
from typing import Any, Dict
from datetime import datetime, timezone

from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.email_analysis import EmailAnalysis
from app.schemas.agent_result import AgentExecutionResult, AgentStatus
from app.agents.email_agent import EmailNLPAgent
from app.agents.header_agent import HeaderAuthAgent
from app.agents.url_agent import UrlDomainAgent
from app.agents.sender_agent import SenderIpAgent
from app.agents.attachment_agent import AttachmentAgent
from app.agents.threat_intel_agent import ThreatIntelAgent
from pydantic import ValidationError


logger = logging.getLogger(__name__)

# Configurable limits for input truncation to protect LLM context windows
MAX_URLS = 50
MAX_ATTACHMENTS = 10

class OrchestrationError(Exception):
    pass

class NonRetryableError(Exception):
    pass

class LLMProviderError(Exception):
    """Exception raised for transient LLM provider issues (timeouts, network)."""
    pass

class AgentOrchestrator:
    """
    Coordinates the execution of specialist agents concurrently for a single email.
    """

    def __init__(self):
        self.agents = {
            "email_nlp": EmailNLPAgent(),
            "header_auth": HeaderAuthAgent(),
            "url_domain": UrlDomainAgent(),
            "sender_ip": SenderIpAgent(),
            "attachment": AttachmentAgent(),
            "threat_intel": ThreatIntelAgent(),
        }

    # Define retry policies for individual agents
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(LLMProviderError),
        reraise=True
    )
    async def _execute_single_agent(
        self, 
        agent_key: str, 
        analysis: EmailAnalysis, 
        analysis_run_id: str, 
        kwargs: dict
    ) -> AgentExecutionResult:
        agent = self.agents[agent_key]
        start_time = datetime.now(timezone.utc)
        logger.info(f"agent_started: {agent.agent_name} for run {analysis_run_id}")

        try:
            # Enforce strict 30-second timeout per agent invocation
            result = await asyncio.wait_for(agent.run(analysis, **kwargs), timeout=30.0)
            
            if result.status == AgentStatus.FAILED:
                # If it's a validation error, we do not retry infinitely. We just accept failure.
                logger.warning(f"agent_failed: {agent.agent_name} failed with {result.error_message}")
            else:
                logger.info(f"agent_completed: {agent.agent_name} for run {analysis_run_id}")
                
            # Note: in a real implementation, we might raise LLMProviderError based on exact exceptions caught in agent.run.
            # Currently agent.run catches Exception and returns FAILED status, so tenacity won't trigger unless we modify agent.run
            # or inspect the error message here. For step 9 requirements, if it's network-related, we could raise LLMProviderError.
            if result.status == AgentStatus.FAILED and ("network" in str(result.error_message).lower() or "timeout" in str(result.error_message).lower() or "rate limit" in str(result.error_message).lower()):
                raise LLMProviderError(result.error_message)

            return result

        except asyncio.TimeoutError:
            logger.error(f"agent_timeout: {agent.agent_name} for run {analysis_run_id}")
            raise LLMProviderError(f"Agent {agent.agent_name} timed out after 30s")
        except Exception as e:
            if isinstance(e, LLMProviderError):
                raise e
            logger.error(f"agent_failed: {agent.agent_name} unexpectedly failed: {e}")
            # Fallback result
            return AgentExecutionResult(
                workspace_id=analysis.workspace_id,
                email_analysis_id=analysis.id,
                agent_name=agent.agent_name,
                agent_version=agent.agent_version,
                prompt_version=agent.prompt_version,
                model="unknown",
                status=AgentStatus.FAILED,
                error_message=str(e)[:500]
            )

    async def orchestrate(
        self, 
        db: AsyncSession, 
        workspace_id: uuid.UUID, 
        email_analysis_id: uuid.UUID, 
        analysis_run_id: str
    ) -> Dict[str, Any]:
        """
        Main entry point for triage orchestration.
        """
        logger.info(f"triage_started for analysis_id={email_analysis_id}, run_id={analysis_run_id}")

        # 1. Fetch analysis with strict workspace isolation
        stmt = select(EmailAnalysis).where(
            EmailAnalysis.id == email_analysis_id,
            EmailAnalysis.workspace_id == workspace_id
        )
        result = await db.execute(stmt)
        analysis = result.scalar_one_or_none()

        if not analysis:
            logger.error(f"Security Violation or Missing Record: EmailAnalysis {email_analysis_id} not found in Workspace {workspace_id}")
            raise OrchestrationError("Email analysis not found or workspace mismatch")

        # 2. Reconstruct context from deterministic pipeline data
        # For this prototype, we simulate fetching the deterministic data (URLs, attachments, intel).
        # In a real app, this data might be loaded via ORM relationships like `analysis.attachments`.
        
        # We ensure bounded context.
        mock_urls = getattr(analysis, "extracted_urls", [])[:MAX_URLS]
        mock_attachments = getattr(analysis, "attachments_data", [])[:MAX_ATTACHMENTS]

        enrichment_data = getattr(analysis, "enrichment_data", {}) or {}

        kwargs_map = {
            "email_nlp": {
                "parsed_body": getattr(analysis, "ai_summary", "Email body placeholder") or "Email body placeholder",
                "has_malicious_iocs": False,
                "extracted_urls": mock_urls,
                "extracted_ips": [],
            },
            "header_auth": {},
            "url_domain": {
                "urls": mock_urls,
                "url_intelligence": enrichment_data.get("url_intelligence", {}),
                "raw_urls_context": [],
            },
            "sender_ip": {
                "ip_intelligence": enrichment_data.get("ip_intelligence", {}),
                "domain_intelligence": enrichment_data.get("domain_intelligence", {}),
                "raw_sender_header": f"{getattr(analysis, 'sender_display_name', '')} <{getattr(analysis, 'sender_email', '')}>"
            },
            "attachment": {
                "attachments": mock_attachments,
            },
            "threat_intel": {
                "threat_intelligence": enrichment_data.get("threat_intelligence", {}),
                "ioc_context": [],
            },
        }

        # 3. Concurrently execute all agents
        tasks = []
        for key in self.agents.keys():
            task = self._execute_single_agent(key, analysis, analysis_run_id, kwargs_map[key])
            tasks.append(task)

        # return_exceptions=True ensures one agent failure does not crash the gather loop
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 4. Aggregate results
        agents_status = {}
        for idx, key in enumerate(self.agents.keys()):
            res = results[idx]
            
            if isinstance(res, Exception):
                logger.error(f"agent_failed: {key} raised an unhandled exception: {res}")
                agents_status[key] = "FAILED"
            else:
                agents_status[key] = res.status.value

        logger.info(f"triage_completed for analysis_id={email_analysis_id}, run_id={analysis_run_id}")

        return {
            "workspace_id": str(workspace_id),
            "email_analysis_id": str(email_analysis_id),
            "analysis_run_id": analysis_run_id,
            "status": "COMPLETED",
            "agents": agents_status
        }
