"""
SentinelTrace Backend — AI / LLM Service

Abstract interface for LLM reasoning and threat classification.
SECURITY INVARIANT: This service NEVER receives credentials, tokens,
JWT secrets, database passwords, or raw API keys in its prompts.
Only sanitized metadata is passed to the LLM.
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel

from app.core.config import get_settings
from app.core.logging import get_logger

settings = get_settings()
logger = get_logger("sentineltrace.ai")


# ── Sanitized Input Schema ────────────────────────────────────────────────────

class EmailThreatContext:
    """
    Sanitized, credential-free representation of an email for LLM analysis.
    Contains ONLY metadata needed for threat classification.
    """

    def __init__(
        self,
        subject: str | None,
        sender_email: str | None,
        sender_domain: str | None,
        reply_to: str | None,
        recipient_count: int,
        spf_result: str | None,
        dkim_result: str | None,
        dmarc_result: str | None,
        extracted_urls: list[str],
        extracted_ips: list[str],
        attachment_count: int,
        attachment_names: list[str],
        attachment_types: list[str],
        body_text_snippet: str | None,
        threat_intel_summary: dict[str, Any],
    ) -> None:
        self.subject = subject
        self.sender_email = sender_email
        self.sender_domain = sender_domain
        self.reply_to = reply_to
        self.recipient_count = recipient_count
        self.spf_result = spf_result
        self.dkim_result = dkim_result
        self.dmarc_result = dmarc_result
        # Limit URLs/IPs to avoid token explosion
        self.extracted_urls = extracted_urls[:20]
        self.extracted_ips = extracted_ips[:10]
        self.attachment_count = attachment_count
        self.attachment_names = attachment_names
        self.attachment_types = attachment_types
        # Truncate body to avoid leaking sensitive data
        self.body_text_snippet = (body_text_snippet or "")[:2000]
        self.threat_intel_summary = threat_intel_summary

    def to_prompt_dict(self) -> dict[str, Any]:
        """Convert to a safe dict for LLM prompt injection. NO credentials."""
        return {
            "subject": self.subject,
            "sender_email": self.sender_email,
            "sender_domain": self.sender_domain,
            "reply_to": self.reply_to,
            "recipient_count": self.recipient_count,
            "authentication": {
                "spf": self.spf_result,
                "dkim": self.dkim_result,
                "dmarc": self.dmarc_result,
            },
            "extracted_urls": self.extracted_urls,
            "extracted_ips": self.extracted_ips,
            "attachments": {
                "count": self.attachment_count,
                "names": self.attachment_names,
                "types": self.attachment_types,
            },
            "body_snippet": self.body_text_snippet,
            "threat_intelligence": self.threat_intel_summary,
        }


# ── Analysis Results ──────────────────────────────────────────────────────────

class ThreatClassificationResult:
    def __init__(
        self,
        threat_category: str,
        severity: str,
        confidence_score: float,
        summary: str,
        reasoning: str,
        indicators: list[str],
        model_used: str,
    ) -> None:
        self.threat_category = threat_category
        self.severity = severity
        self.confidence_score = confidence_score
        self.summary = summary
        self.reasoning = reasoning
        self.indicators = indicators
        self.model_used = model_used


# ── Abstract LLM Interface ────────────────────────────────────────────────────

class LLMProvider(ABC):
    """Abstract LLM provider. Swap implementations without changing business logic."""

    @abstractmethod
    async def classify_threat(self, context: EmailThreatContext) -> ThreatClassificationResult:
        """Classify email threat and return structured analysis."""
        ...

    @abstractmethod
    async def generate_summary(
        self,
        context: EmailThreatContext,
        classification: ThreatClassificationResult,
    ) -> str:
        """Generate a human-readable threat summary for the SOC analyst."""
        ...

    @abstractmethod
    async def execute_agent(
        self,
        system_prompt: str,
        trusted_evidence: dict[str, Any],
        untrusted_content: str | None,
        response_schema: type[BaseModel],
    ) -> BaseModel:
        """Execute a specific AI agent with strict boundaries and structured output."""
        ...


# ── OpenAI-Compatible Adapter ─────────────────────────────────────────────────

CLASSIFICATION_SYSTEM_PROMPT = """You are SentinelTrace, an expert cybersecurity AI specializing in email threat analysis for Security Operations Centers (SOCs).

Your task is to analyze email metadata and threat intelligence data and classify the threat.

IMPORTANT RULES:
- Analyze ONLY the provided metadata. Do not make up information.
- Never request, generate, or reference credentials, passwords, or API keys.
- Return ONLY valid JSON matching the schema below.
- Be conservative: when uncertain, err toward higher severity.

Output JSON schema:
{
  "threat_category": "PHISHING|SPEAR_PHISHING|BEC|MALWARE|SPAM|RANSOMWARE|CREDENTIAL_HARVEST|SOCIAL_ENGINEERING|UNKNOWN|BENIGN",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "confidence_score": 0.0-1.0,
  "reasoning": "Step-by-step analysis of why this classification was made",
  "key_indicators": ["list", "of", "specific", "indicators", "that", "drove", "this", "classification"]
}"""

SUMMARY_SYSTEM_PROMPT = """You are a cybersecurity analyst assistant for a Security Operations Center.
Write a concise, professional threat summary for a SOC analyst.
The summary should:
- Be 2-4 paragraphs
- Start with the threat verdict and severity
- Explain the attack vector and technique
- List actionable remediation steps
- Use professional, clear language
- Never include credentials, API keys, or raw secrets"""


class OpenAICompatibleAdapter(LLMProvider):
    """
    Adapter for any OpenAI-compatible API endpoint.
    Supports OpenAI, Azure OpenAI, local LM Studio, Ollama, etc.
    """

    def __init__(self) -> None:
        try:
            from openai import AsyncOpenAI
            self._client = AsyncOpenAI(
                api_key=settings.LLM_API_KEY,
                base_url=settings.LLM_BASE_URL,
            )
        except ImportError:
            self._client = None
            logger.warning("openai_not_installed", msg="AI features disabled")

    async def classify_threat(self, context: EmailThreatContext) -> ThreatClassificationResult:
        if not self._client or not settings.LLM_API_KEY:
            return self._fallback_classification()

        prompt_data = json.dumps(context.to_prompt_dict(), indent=2, default=str)

        try:
            response = await self._client.chat.completions.create(
                model=settings.CLASSIFIER_MODEL,
                messages=[
                    {"role": "system", "content": CLASSIFICATION_SYSTEM_PROMPT},
                    {"role": "user", "content": f"Analyze this email:\n\n{prompt_data}"},
                ],
                max_tokens=1024,
                temperature=settings.LLM_TEMPERATURE,
                response_format={"type": "json_object"},
            )

            raw = response.choices[0].message.content or "{}"
            result = json.loads(raw)

            return ThreatClassificationResult(
                threat_category=result.get("threat_category", "UNKNOWN"),
                severity=result.get("severity", "MEDIUM"),
                confidence_score=float(result.get("confidence_score", 0.5)),
                summary="",  # Will be filled by generate_summary
                reasoning=result.get("reasoning", ""),
                indicators=result.get("key_indicators", []),
                model_used=settings.CLASSIFIER_MODEL,
            )
        except Exception as e:
            logger.error("llm_classification_error", error=str(e))
            return self._fallback_classification()

    async def generate_summary(
        self,
        context: EmailThreatContext,
        classification: ThreatClassificationResult,
    ) -> str:
        if not self._client or not settings.LLM_API_KEY:
            return self._fallback_summary(classification)

        prompt_data = {
            "email_context": context.to_prompt_dict(),
            "classification": {
                "threat_category": classification.threat_category,
                "severity": classification.severity,
                "confidence_score": classification.confidence_score,
                "key_indicators": classification.indicators,
            },
        }

        try:
            response = await self._client.chat.completions.create(
                model=settings.LLM_MODEL,
                messages=[
                    {"role": "system", "content": SUMMARY_SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps(prompt_data, default=str)},
                ],
                max_tokens=settings.LLM_MAX_TOKENS,
                temperature=settings.LLM_TEMPERATURE,
            )
            return response.choices[0].message.content or self._fallback_summary(classification)
        except Exception as e:
            logger.error("llm_summary_error", error=str(e))
            return self._fallback_summary(classification)

    async def execute_agent(
        self,
        system_prompt: str,
        trusted_evidence: dict[str, Any],
        untrusted_content: str | None,
        response_schema: type[BaseModel],
    ) -> BaseModel:
        if not self._client or not settings.LLM_API_KEY:
            raise ValueError("LLM provider not configured or unavailable")

        # Construct prompt injection boundaries
        user_content = "<TRUSTED_EVIDENCE>\n"
        user_content += json.dumps(trusted_evidence, indent=2, default=str)
        user_content += "\n</TRUSTED_EVIDENCE>\n"
        
        if untrusted_content:
            user_content += "\n<UNTRUSTED_CONTENT>\n"
            user_content += str(untrusted_content)
            user_content += "\n</UNTRUSTED_CONTENT>\n"
            
        schema_json = json.dumps(response_schema.model_json_schema(), indent=2)
        system_content = (
            f"<SYSTEM_INSTRUCTIONS>\n{system_prompt}\n\n"
            f"You MUST return ONLY valid JSON matching this exact schema:\n{schema_json}\n"
            "</SYSTEM_INSTRUCTIONS>"
        )

        try:
            response = await self._client.chat.completions.create(
                model=settings.CLASSIFIER_MODEL,
                messages=[
                    {"role": "system", "content": system_content},
                    {"role": "user", "content": user_content},
                ],
                max_tokens=2048,
                temperature=0.1,  # Low temperature for deterministic agent extraction
                response_format={"type": "json_object"},
            )
            raw = response.choices[0].message.content or "{}"
            return response_schema.model_validate_json(raw)
        except Exception as e:
            logger.error("agent_execution_error", error=str(e))
            raise

    def _fallback_classification(self) -> ThreatClassificationResult:
        return ThreatClassificationResult(
            threat_category="UNKNOWN",
            severity="MEDIUM",
            confidence_score=0.0,
            summary="AI analysis unavailable. Manual review required.",
            reasoning="LLM provider not configured or unavailable.",
            indicators=[],
            model_used="none",
        )

    def _fallback_summary(self, classification: ThreatClassificationResult) -> str:
        return (
            f"Threat Classification: {classification.threat_category} "
            f"(Severity: {classification.severity})\n\n"
            "AI-generated summary is unavailable. "
            "Please review the threat indicators and enrichment data manually."
        )


# ── Service Factory ───────────────────────────────────────────────────────────

def get_ai_service() -> LLMProvider:
    """Return the configured LLM provider instance."""
    provider_map = {
        "openai": OpenAICompatibleAdapter,
        "anthropic": OpenAICompatibleAdapter,  # Use OpenAI-compat endpoint
        "local": OpenAICompatibleAdapter,
    }
    cls = provider_map.get(settings.LLM_PROVIDER, OpenAICompatibleAdapter)
    return cls()
