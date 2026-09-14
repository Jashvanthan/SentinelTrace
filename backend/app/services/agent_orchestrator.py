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

        # 1. Fetch analysis with strict workspace isolation and eager load relations
        from sqlalchemy.orm import selectinload
        stmt = (
            select(EmailAnalysis)
            .where(
                EmailAnalysis.id == email_analysis_id,
                EmailAnalysis.workspace_id == workspace_id
            )
            .options(
                selectinload(EmailAnalysis.iocs),
                selectinload(EmailAnalysis.attachments),
            )
        )
        result = await db.execute(stmt)
        analysis = result.scalar_one_or_none()

        if not analysis:
            logger.error(f"Security Violation or Missing Record: EmailAnalysis {email_analysis_id} not found in Workspace {workspace_id}")
            raise OrchestrationError("Email analysis not found or workspace mismatch")

        # 2. Reconstruct authentic context from deterministic pipeline data
        iocs_list = list(analysis.iocs or [])
        real_urls = [
            ioc.value for ioc in iocs_list 
            if str(ioc.ioc_type).upper() in ("URL", "IOCTYPE.URL")
        ][:MAX_URLS]

        real_ips = [
            ioc.value for ioc in iocs_list 
            if str(ioc.ioc_type).upper() in ("IP_ADDRESS", "IP", "IPADDRESS", "IOCTYPE.IP_ADDRESS")
        ]
        geo_data = getattr(analysis, "geo_data", {}) or {}
        if not real_ips and isinstance(geo_data, dict):
            for item in geo_data.get("ips", []):
                if isinstance(item, dict) and item.get("ip_address"):
                    real_ips.append(item["ip_address"])
            if geo_data.get("primary_ip"):
                real_ips.insert(0, geo_data["primary_ip"])
        real_ips = list(dict.fromkeys(real_ips))[:20]

        real_attachments = [
            {
                "filename": att.filename,
                "content_type": att.content_type,
                "size_bytes": att.size_bytes,
                "sha256_hash": att.sha256_hash,
                "is_malicious": att.is_malicious,
                "vt_detections": att.vt_detections,
                "vt_total_engines": att.vt_total_engines,
            }
            for att in (analysis.attachments or [])
        ][:MAX_ATTACHMENTS]

        enrichment_data = getattr(analysis, "enrichment_data", {}) or {}
        has_malicious = any(ioc.is_malicious for ioc in iocs_list) or any(att.get("is_malicious") for att in real_attachments)

        primary_ip = geo_data.get("primary_ip") or geo_data.get("ip_address") or (real_ips[0] if real_ips else None)
        ip_intelligence = {
            "primary_ip": primary_ip,
            "country": geo_data.get("country"),
            "city": geo_data.get("city"),
            "isp": geo_data.get("isp"),
            "org": geo_data.get("org"),
            "asn": geo_data.get("asn"),
            "routing_type": geo_data.get("routing_type"),
            "routing_label": geo_data.get("routing_label"),
            "virustotal": enrichment_data.get("virustotal"),
            "abuseipdb": enrichment_data.get("abuseipdb"),
            "shodan": enrichment_data.get("shodan"),
            "transit_hops": geo_data.get("ips", []),
        }

        domain_intelligence = {
            "sender_domain": analysis.sender_domain,
            "spf_result": analysis.spf_result,
            "dkim_result": analysis.dkim_result,
            "dmarc_result": analysis.dmarc_result,
            "intel": enrichment_data.get(f"domain_{analysis.sender_domain}"),
        }

        body_snippet = analysis.ai_summary or analysis.subject or "Legitimate email correspondence"

        kwargs_map = {
            "email_nlp": {
                "parsed_body": body_snippet,
                "has_malicious_iocs": has_malicious,
                "extracted_urls": real_urls,
                "extracted_ips": real_ips,
            },
            "header_auth": {},
            "url_domain": {
                "urls": real_urls,
                "url_intelligence": {
                    url: enrichment_data.get(f"url_{url[:50]}") for url in real_urls
                },
                "raw_urls_context": real_urls,
            },
            "sender_ip": {
                "ip_intelligence": ip_intelligence,
                "domain_intelligence": domain_intelligence,
                "raw_sender_header": f"{getattr(analysis, 'sender_display_name', '') or ''} <{getattr(analysis, 'sender_email', '') or ''}>"
            },
            "attachment": {
                "attachments": real_attachments,
            },
            "threat_intel": {
                "threat_intelligence": {
                    "summary": enrichment_data,
                    "iocs": [
                        {
                            "type": str(ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else ioc.ioc_type),
                            "value": ioc.value,
                            "is_malicious": ioc.is_malicious,
                            "threat_score": ioc.threat_score,
                            "enrichment": ioc.enrichment_data,
                        }
                        for ioc in iocs_list
                    ],
                },
                "ioc_context": [ioc.value for ioc in iocs_list],
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
