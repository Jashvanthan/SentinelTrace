"""
SentinelTrace Backend — Base AI Agent
"""
from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from typing import Any

from app.models.email_analysis import EmailAnalysis
from app.schemas.agent_result import AgentExecutionResult, AgentStatus, BaseAgentResponse
from app.services.ai_service import get_ai_service


class BaseAgent(ABC):
    """
    Abstract base class for all SentinelTrace AI Agents.
    """

    @property
    @abstractmethod
    def agent_name(self) -> str:
        """Name of the agent (e.g., 'email_nlp_agent')."""
        ...

    @property
    @abstractmethod
    def agent_version(self) -> str:
        """Version of the agent logic (e.g., '1.0')."""
        ...

    @property
    @abstractmethod
    def prompt_version(self) -> str:
        """Version of the system prompt (e.g., 'email_nlp_v1')."""
        ...

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """The system prompt for this agent."""
        ...

    @abstractmethod
    def extract_trusted_evidence(self, analysis: EmailAnalysis, **kwargs: Any) -> dict[str, Any]:
        """Extract only the deterministic facts relevant to this agent."""
        ...

    @abstractmethod
    def extract_untrusted_content(self, analysis: EmailAnalysis, **kwargs: Any) -> str | None:
        """Extract untrusted input (e.g., email body) relevant to this agent."""
        ...

    async def run(self, analysis: EmailAnalysis, **kwargs: Any) -> AgentExecutionResult:
        """
        Execute the agent logic safely using the LLM provider.
        """
        start_time = time.monotonic()
        ai_service = get_ai_service()
        if hasattr(ai_service, "_client") and hasattr(ai_service._client, "model"):
            model_name = str(ai_service._client.model)
        else:
            model_name = "unknown"

        result = AgentExecutionResult(
            workspace_id=analysis.workspace_id,
            email_analysis_id=analysis.id,
            agent_name=self.agent_name,
            agent_version=self.agent_version,
            prompt_version=self.prompt_version,
            model=model_name,
            status=AgentStatus.RUNNING,
        )

        try:
            trusted_evidence = self.extract_trusted_evidence(analysis, **kwargs)
            untrusted_content = self.extract_untrusted_content(analysis, **kwargs)

            response: BaseAgentResponse = await ai_service.execute_agent(
                system_prompt=self.system_prompt,
                trusted_evidence=trusted_evidence,
                untrusted_content=untrusted_content,
                response_schema=BaseAgentResponse,
            )

            result.status = AgentStatus.COMPLETED
            result.risk_score = response.risk_score
            result.confidence = response.confidence
            result.classification = response.classification
            result.findings = response.findings
            result.evidence = response.evidence
            result.recommendations = response.recommendations
            result.metadata = response.metadata

        except Exception as e:
            result.status = AgentStatus.FAILED
            result.error_message = str(e)

        result.duration_ms = int((time.monotonic() - start_time) * 1000)
        return result
