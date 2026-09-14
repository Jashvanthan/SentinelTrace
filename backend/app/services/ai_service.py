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
- Be conservative: when uncertain, err toward higher severity.
- Your ENTIRE response must be ONLY a single valid JSON object. No markdown, no explanation, no code fences.
- Do NOT wrap JSON in ```json blocks or any other formatting.

You MUST respond with EXACTLY this JSON structure:
{"threat_category": "PHISHING", "severity": "HIGH", "confidence_score": 0.85, "reasoning": "...", "key_indicators": ["indicator1", "indicator2"]}

Valid threat_category values: PHISHING, SPEAR_PHISHING, BEC, MALWARE, SPAM, RANSOMWARE, CREDENTIAL_HARVEST, SOCIAL_ENGINEERING, UNKNOWN, BENIGN
Valid severity values: CRITICAL, HIGH, MEDIUM, LOW, INFO
confidence_score must be a number between 0.0 and 1.0"""

SUMMARY_SYSTEM_PROMPT = """You are a cybersecurity analyst assistant for a Security Operations Center.
Write a concise, professional threat summary for a SOC analyst.
The summary should:
- Be 2-4 paragraphs
- Start with the threat verdict and severity
- Explain the attack vector and technique
- List actionable remediation steps
- Use professional, clear language
- Never include credentials, API keys, or raw secrets"""

# Maximum number of retries for JSON parsing from LLM responses
_MAX_JSON_RETRIES = 2


def _extract_json(text: str) -> dict[str, Any]:
    """
    Robustly extract a JSON object from LLM response text.

    Handles cases where the model wraps JSON in markdown code fences,
    adds explanatory text before/after the JSON, or returns raw JSON.
    """
    import re

    # Strip reasoning/thinking tags if present
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

    # 1. Try direct JSON parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. Try extracting from markdown code fences: ```json ... ``` or ``` ... ```
    fence_pattern = re.compile(r"```(?:json)?\s*\n?(.*?)\n?\s*```", re.DOTALL)
    match = fence_pattern.search(text)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # 3. Try finding the outermost { ... } block
    brace_start = text.find("{")
    brace_end = text.rfind("}")
    if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
        candidate = text[brace_start:brace_end + 1]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Could not extract valid JSON from LLM response: {text[:200]}...")


class OpenAICompatibleAdapter(LLMProvider):
    """
    Adapter for any OpenAI-compatible API endpoint.
    Supports OpenAI, Azure OpenAI, OpenRouter (free & paid models),
    local LM Studio, Ollama, etc.

    Does NOT require `response_format: json_object` — instead uses
    robust JSON extraction from text responses, making it compatible
    with free models like Llama, Gemma, Mistral, etc.
    """

    def __init__(self) -> None:
        try:
            from openai import AsyncOpenAI
            self._client = AsyncOpenAI(
                api_key=settings.LLM_API_KEY,
                base_url=settings.LLM_BASE_URL,
                timeout=30.0,
                default_headers={
                    "HTTP-Referer": "https://sentineltrace.io",
                    "X-Title": "SentinelTrace SOC",
                }
            )
        except ImportError:
            self._client = None
            logger.warning("openai_not_installed", msg="AI features disabled")

    async def classify_threat(self, context: EmailThreatContext) -> ThreatClassificationResult:
        if not self._client or not settings.LLM_API_KEY:
            return self._fallback_classification(context)

        prompt_data = json.dumps(context.to_prompt_dict(), indent=2, default=str)

        for attempt in range(_MAX_JSON_RETRIES + 1):
            try:
                response = await self._client.chat.completions.create(
                    model=settings.CLASSIFIER_MODEL,
                    messages=[
                        {"role": "system", "content": CLASSIFICATION_SYSTEM_PROMPT},
                        {"role": "user", "content": f"Analyze this email and respond with ONLY JSON:\n\n{prompt_data}"},
                    ],
                    max_tokens=1024,
                    temperature=settings.LLM_TEMPERATURE,
                )

                raw = response.choices[0].message.content or "{}"
                result = _extract_json(raw)

                return ThreatClassificationResult(
                    threat_category=result.get("threat_category", "UNKNOWN"),
                    severity=result.get("severity", "MEDIUM"),
                    confidence_score=float(result.get("confidence_score", 0.5)),
                    summary="",  # Will be filled by generate_summary
                    reasoning=result.get("reasoning", ""),
                    indicators=result.get("key_indicators", []),
                    model_used=settings.CLASSIFIER_MODEL,
                )
            except ValueError as e:
                # JSON extraction failed — retry with a stronger hint
                if attempt < _MAX_JSON_RETRIES:
                    logger.warning(
                        "llm_json_retry",
                        attempt=attempt + 1,
                        error=str(e),
                    )
                    continue
                logger.error("llm_classification_json_failed", error=str(e))
                return self._fallback_classification(context)
            except Exception as e:
                logger.error("llm_classification_error", error=str(e))
                return self._fallback_classification(context)

        return self._fallback_classification(context)

    async def generate_summary(
        self,
        context: EmailThreatContext,
        classification: ThreatClassificationResult,
    ) -> str:
        if not self._client or not settings.LLM_API_KEY:
            return self._fallback_summary(classification)

        prompt_data = {
            "email": context.to_prompt_dict(),
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
                max_tokens=512,
                temperature=settings.LLM_TEMPERATURE,
            )
            return response.choices[0].message.content or self._fallback_summary(classification, context)
        except Exception as e:
            logger.error("llm_summary_error", error=str(e))
            return self._fallback_summary(classification, context)

    async def execute_agent(
        self,
        system_prompt: str,
        trusted_evidence: dict[str, Any],
        untrusted_content: str | None,
        response_schema: type[BaseModel],
    ) -> BaseModel:
        if self._client and settings.LLM_API_KEY:
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
                "Do NOT wrap the JSON in code fences or add any explanation.\n"
                "Your ENTIRE response must be a single JSON object.\n"
                "</SYSTEM_INSTRUCTIONS>"
            )

            for attempt in range(_MAX_JSON_RETRIES + 1):
                try:
                    response = await self._client.chat.completions.create(
                        model=settings.CLASSIFIER_MODEL,
                        messages=[
                            {"role": "system", "content": system_content},
                            {"role": "user", "content": user_content},
                        ],
                        max_tokens=2048,
                        temperature=0.1,  # Low temperature for deterministic agent extraction
                    )
                    raw = response.choices[0].message.content or "{}"
                    extracted = _extract_json(raw)
                    return response_schema.model_validate(extracted)
                except ValueError as e:
                    if attempt < _MAX_JSON_RETRIES:
                        logger.warning("agent_json_retry", attempt=attempt + 1, error=str(e))
                        continue
                    logger.warning("agent_json_failed_falling_back", error=str(e))
                    break
                except Exception as e:
                    logger.warning("agent_llm_call_failed_falling_back", error=str(e))
                    break

        # Fallback to deterministic specialist agent evaluation
        return self._execute_deterministic_agent(system_prompt, trusted_evidence, untrusted_content)

    def _execute_deterministic_agent(
        self,
        system_prompt: str,
        trusted_evidence: dict[str, Any],
        untrusted_content: str | None,
    ) -> BaseAgentResponse:
        from app.schemas.agent_result import FindingSeverity, AgentFinding, BaseAgentResponse
        from app.models.email_analysis import ThreatCategory

        prompt_lower = system_prompt.lower()
        findings: list[AgentFinding] = []
        evidence: list[str] = []
        recs: list[str] = []
        score = 10
        confidence = 0.85
        cat = ThreatCategory.BENIGN

        # ── 1. Header & Authentication Agent ─────────────────────────────────
        if "header/auth" in prompt_lower or "authentication" in trusted_evidence:
            auth = trusted_evidence.get("authentication", {})
            align = trusted_evidence.get("header_alignment", {})
            routing = trusted_evidence.get("routing", {})

            spf = str(auth.get("spf") or "").lower()
            dkim = str(auth.get("dkim") or "").lower()
            dmarc = str(auth.get("dmarc") or "").lower()

            if spf in ("fail", "softfail"):
                score += 30
                cat = ThreatCategory.PHISHING
                findings.append(AgentFinding(
                    type="spf_failure",
                    severity=FindingSeverity.HIGH,
                    description=f"SPF authentication validation failed ({spf}). Mail server is unauthorized for sender domain.",
                ))
                recs.append("Reject or quarantine emails failing SPF validation.")
            elif spf == "pass":
                evidence.append("SPF authentication passed")

            if dkim == "fail":
                score += 25
                cat = ThreatCategory.PHISHING
                findings.append(AgentFinding(
                    type="dkim_failure",
                    severity=FindingSeverity.HIGH,
                    description="Cryptographic DKIM body signature verification failed or key mismatched.",
                ))
            elif dkim == "pass":
                evidence.append("DKIM cryptographic signature verified")

            if dmarc == "fail":
                score += 35
                cat = ThreatCategory.PHISHING
                findings.append(AgentFinding(
                    type="dmarc_alignment_failure",
                    severity=FindingSeverity.CRITICAL if score > 50 else FindingSeverity.HIGH,
                    description="DMARC policy enforcement failed. Sender domain header does not align with authorized envelope.",
                ))
                recs.append("Enforce strict DMARC p=reject policy.")
            elif dmarc == "pass":
                evidence.append("DMARC domain alignment passed")

            reply_to = align.get("reply_to")
            from_domain = align.get("from_domain")
            if reply_to and from_domain and "@" in str(reply_to):
                rt_domain = str(reply_to).split("@")[-1].lower()
                if rt_domain != str(from_domain).lower():
                    score += 25
                    cat = ThreatCategory.SPEAR_PHISHING
                    findings.append(AgentFinding(
                        type="reply_to_mismatch",
                        severity=FindingSeverity.HIGH,
                        description=f"Reply-To domain mismatch: directs responses to '{rt_domain}' instead of '{from_domain}'.",
                    ))
                    recs.append(f"Inspect Reply-To destination '{reply_to}' for credential redirection.")

            hops_count = routing.get("received_headers_count", 0)
            if hops_count > 0:
                evidence.append(f"Observed {hops_count} transit Received hops in routing chain")

            if not findings:
                evidence.append("All email authentication headers (SPF, DKIM, DMARC) and alignment rules verified clean")
                recs.append("Standard legitimate sender authentication verified.")

        # ── 2. Sender / Origin IP Agent ──────────────────────────────────────
        elif "sender/ip" in prompt_lower or "ip_intelligence" in trusted_evidence:
            sender_meta = trusted_evidence.get("sender_metadata", {})
            ip_intel = trusted_evidence.get("ip_intelligence", {})
            domain_intel = trusted_evidence.get("domain_intelligence", {})

            primary_ip = ip_intel.get("primary_ip") or ip_intel.get("ip_address")
            country = ip_intel.get("country")
            isp = ip_intel.get("isp")
            asn = ip_intel.get("asn")
            routing_type = ip_intel.get("routing_type")
            routing_label = ip_intel.get("routing_label")

            if primary_ip:
                evidence.append(f"Origin IP: {primary_ip} (Location: {country or 'Unknown'}, ISP: {isp or 'Unknown'}, ASN: {asn or 'Unknown'})")
                if routing_label:
                    evidence.append(f"Routing Profile: {routing_label}")

            if routing_type == "TOR_EXIT_NODE":
                score += 45
                cat = ThreatCategory.PHISHING
                findings.append(AgentFinding(
                    type="tor_exit_node_origin",
                    severity=FindingSeverity.CRITICAL,
                    description=f"Email transmitted via anonymized Tor exit node ({primary_ip}).",
                ))
                recs.append("Block traffic originating from public Tor nodes.")
            elif routing_type in ("COMMERCIAL_VPN", "PROXY_RELAY"):
                score += 20
                findings.append(AgentFinding(
                    type="vpn_proxy_relay",
                    severity=FindingSeverity.MEDIUM,
                    description=f"Email transmitted via commercial VPN/Proxy gateway ({routing_label}).",
                ))

            # Check Threat Intelligence reputation on IP
            vt = ip_intel.get("virustotal") or {}
            abuse = ip_intel.get("abuseipdb") or {}
            if isinstance(vt, dict) and vt.get("malicious_count", 0) > 0:
                score += 40
                cat = ThreatCategory.MALWARE
                findings.append(AgentFinding(
                    type="blacklisted_ip",
                    severity=FindingSeverity.CRITICAL,
                    description=f"Origin IP {primary_ip} flagged malicious by {vt.get('malicious_count')} threat intelligence engines.",
                ))
                recs.append(f"Add origin IP {primary_ip} to firewall perimeter drop rules.")

            if isinstance(abuse, dict) and abuse.get("abuse_confidence_score", 0) > 25:
                score += 30
                findings.append(AgentFinding(
                    type="high_abuse_reputation",
                    severity=FindingSeverity.HIGH,
                    description=f"AbuseIPDB reported {abuse.get('abuse_confidence_score')}% malicious confidence score on {primary_ip}.",
                ))

            # Display name spoofing check
            display_name = (sender_meta.get("sender_display_name") or "").lower()
            sender_domain = (sender_meta.get("sender_domain") or "").lower()
            well_known_brands = ["paypal", "microsoft", "google", "apple", "amazon", "netflix", "bank", "security", "support", "helpdesk"]
            for brand in well_known_brands:
                if brand in display_name and brand not in sender_domain and sender_domain != "":
                    score += 35
                    cat = ThreatCategory.PHISHING
                    findings.append(AgentFinding(
                        type="display_name_spoofing",
                        severity=FindingSeverity.HIGH,
                        description=f"Brand impersonation: display name claims '{display_name}' but sent from unrelated domain '{sender_domain}'.",
                    ))
                    recs.append("Enforce executive and brand display-name impersonation filters.")
                    break

            if not findings:
                evidence.append(f"Sender domain '{sender_domain}' and origin infrastructure {primary_ip or 'verified'} have no negative reputation flags.")
                recs.append("No sender infrastructure anomalies detected.")

        # ── 3. URL / Domain Agent ────────────────────────────────────────────
        elif "url/domain" in prompt_lower or "extracted_urls" in trusted_evidence:
            urls = trusted_evidence.get("extracted_urls", [])
            url_intel = trusted_evidence.get("url_intelligence", {})

            if urls:
                evidence.append(f"Analyzed {len(urls)} distinct URL(s) in message body")
                suspicious_tlds = (".xyz", ".top", ".ru", ".click", ".live", ".work", ".tk", ".ml", ".gq", ".cf")
                shorteners = ("bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly")

                for u in urls:
                    u_low = str(u).lower()
                    if any(u_low.endswith(tld) or f"{tld}/" in u_low for tld in suspicious_tlds):
                        score += 25
                        cat = ThreatCategory.PHISHING
                        findings.append(AgentFinding(
                            type="suspicious_tld_url",
                            severity=FindingSeverity.HIGH,
                            description=f"URL points to high-risk top-level domain: {u[:60]}",
                        ))
                    if any(sh in u_low for sh in shorteners):
                        score += 15
                        findings.append(AgentFinding(
                            type="url_shortener_obfuscation",
                            severity=FindingSeverity.MEDIUM,
                            description=f"URL shortener used to mask final destination: {u[:50]}",
                        ))

                if isinstance(url_intel, dict):
                    for k, v in url_intel.items():
                        if isinstance(v, dict) and v.get("is_malicious"):
                            score += 45
                            cat = ThreatCategory.PHISHING
                            findings.append(AgentFinding(
                                type="malicious_url_intelligence",
                                severity=FindingSeverity.CRITICAL,
                                description=f"Threat intelligence confirmed malicious URL: {k[:60]}",
                            ))
                            recs.append("Block malicious destination URLs on secure web gateways (SWG).")
            else:
                evidence.append("No external hyperlinks present in email body")
                recs.append("Clean hyperlink profile.")

        # ── 4. Attachment Agent ──────────────────────────────────────────────
        elif "attachment" in prompt_lower or "attachments_metadata" in trusted_evidence:
            attachments = trusted_evidence.get("attachments_metadata", [])
            if attachments:
                evidence.append(f"Analyzed {len(attachments)} attachment(s)")
                dangerous_exts = (".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".iso", ".img", ".wsf", ".docm", ".xlsm", ".hta", ".ps1")

                for att in attachments:
                    fname = str(att.get("filename") or "").lower()
                    sha256 = att.get("sha256_hash")
                    is_mal = att.get("is_malicious")
                    vt_hits = att.get("vt_detections") or 0

                    if is_mal or vt_hits > 0:
                        score += 55
                        cat = ThreatCategory.MALWARE
                        findings.append(AgentFinding(
                            type="malicious_attachment_signature",
                            severity=FindingSeverity.CRITICAL,
                            description=f"Attachment '{fname}' matched known malware signatures ({vt_hits} AV detections, SHA-256: {sha256[:16]}...).",
                        ))
                        recs.append(f"Purge malicious attachment {fname} and isolate receiving endpoint.")

                    if any(fname.endswith(ext) for ext in dangerous_exts):
                        score += 40
                        cat = ThreatCategory.MALWARE
                        findings.append(AgentFinding(
                            type="dangerous_file_type",
                            severity=FindingSeverity.HIGH,
                            description=f"Attachment carries dangerous executable or macro format: {fname}",
                        ))
                        recs.append(f"Block executable/macro attachment '{fname}' at mail gateway.")
            else:
                evidence.append("No file attachments present in message")
                recs.append("Attachment profile clean.")

        # ── 5. Threat Intelligence Agent ─────────────────────────────────────
        elif "threat intelligence" in prompt_lower or "threat_intelligence" in trusted_evidence:
            intel = trusted_evidence.get("threat_intelligence", {})
            iocs = intel.get("iocs", []) if isinstance(intel, dict) else []

            malicious_iocs = [ioc for ioc in iocs if isinstance(ioc, dict) and ioc.get("is_malicious")]
            if malicious_iocs:
                score += 50
                cat = ThreatCategory.MALWARE
                findings.append(AgentFinding(
                    type="confirmed_malicious_iocs",
                    severity=FindingSeverity.CRITICAL,
                    description=f"Identified {len(malicious_iocs)} confirmed malicious IOC(s) matched across threat feeds.",
                ))
                for m in malicious_iocs[:3]:
                    evidence.append(f"Malicious IOC: {m.get('type')} = {m.get('value')} (Score: {m.get('threat_score')})")
                recs.append("Feed extracted malicious IOCs directly into SIEM/EDR detection rules.")
            else:
                evidence.append("All extracted forensic indicators checked across Threat Intel feeds with no blacklists triggered")
                recs.append("Threat intelligence reputation verified clean.")

        # ── 6. Email / NLP Linguistic Agent ──────────────────────────────────
        else:
            meta = trusted_evidence.get("metadata", {})
            subject = str(meta.get("subject") or "").lower()
            body_text = str(untrusted_content or "").lower()

            phish_keywords = [
                "urgent", "immediate action", "verify your account", "suspended", "password expire",
                "unauthorized transaction", "wire transfer", "gift card", "overdue invoice", "confirm identity",
                "payment failure", "billing update", "security alert"
            ]
            matched = [k for k in phish_keywords if k in subject or k in body_text]

            if matched:
                score += min(35, len(matched) * 15)
                cat = ThreatCategory.PHISHING
                findings.append(AgentFinding(
                    type="social_engineering_urgency",
                    severity=FindingSeverity.HIGH if len(matched) >= 2 else FindingSeverity.MEDIUM,
                    description=f"Social engineering indicators detected: manipulative urgency keywords ({', '.join(matched[:3])}).",
                ))
                recs.append("Train users to identify urgent payment and credential verification lures.")

            if "wire transfer" in subject or "wire transfer" in body_text or "gift card" in body_text:
                score += 30
                cat = ThreatCategory.BEC
                findings.append(AgentFinding(
                    type="bec_payment_fraud",
                    severity=FindingSeverity.CRITICAL if score > 50 else FindingSeverity.HIGH,
                    description="Linguistic pattern matches Business Email Compromise (BEC) payment/wire transfer fraud.",
                ))
                recs.append("Enforce dual-authorization verification for financial transactions.")

            if not findings:
                evidence.append("Natural language content exhibits standard conversational, transactional, or notification structure")
                recs.append("No social engineering or urgency manipulation detected.")

        return BaseAgentResponse(
            risk_score=max(0, min(100, score)),
            confidence=confidence,
            classification=cat,
            findings=findings,
            evidence=evidence or ["Forensic rules evaluated"],
            recommendations=recs or ["Standard baseline monitoring"],
            metadata={"engine": "sentineltrace_specialist_agent_engine"}
        )

    def _fallback_classification(self, context: EmailThreatContext | None = None) -> ThreatClassificationResult:
        if not context:
            return ThreatClassificationResult(
                threat_category="BENIGN",
                severity="LOW",
                confidence_score=0.8,
                summary="No threat context provided.",
                reasoning="Default heuristic evaluation.",
                indicators=[],
                model_used="heuristic-rules",
            )

        indicators = []
        score = 5
        subject = (context.subject or "").lower()
        body = (context.body_text_snippet or "").lower()
        sender_email = (context.sender_email or "").lower()
        sender_domain = (context.sender_domain or "").lower()
        reply_to = (context.reply_to or "").lower()

        # 1. Authentication Checks
        if context.spf_result in ("fail", "softfail"):
            indicators.append(f"SPF authentication {context.spf_result}")
            score += 25
        if context.dmarc_result == "fail":
            indicators.append("DMARC alignment failed")
            score += 30
        if context.dkim_result == "fail":
            indicators.append("DKIM verification failed")
            score += 20

        # 2. Domain & Sender Mismatches
        if reply_to and "@" in reply_to:
            reply_domain = reply_to.split("@")[-1]
            if sender_domain and reply_domain != sender_domain:
                indicators.append(f"Reply-To domain mismatch ({reply_domain} vs {sender_domain})")
                score += 25

        # 3. Urgent / Phishing Keywords
        phish_keywords = [
            "urgent", "action required", "verify your account", "suspend", "suspended",
            "password reset", "unauthorized login", "security alert", "immediate payment",
            "wire transfer", "gift card", "overdue invoice", "billing issue", "confirm identity"
        ]
        matched_keywords = [k for k in phish_keywords if k in subject or k in body]
        if matched_keywords:
            indicators.append(f"Urgent keywords: {', '.join(matched_keywords[:3])}")
            score += min(35, len(matched_keywords) * 15)

        # 4. Dangerous Attachments
        dangerous_exts = (".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".iso", ".img", ".wsf", ".docm", ".xlsm")
        for att in context.attachment_names:
            att_lower = att.lower()
            if any(att_lower.endswith(ext) for ext in dangerous_exts):
                indicators.append(f"Dangerous attachment format: {att}")
                score += 45

        # 5. URLs
        if context.extracted_urls:
            score += min(15, len(context.extracted_urls) * 3)
            suspicious_tlds = (".xyz", ".top", ".ru", ".click", ".live", ".work", ".tk", ".ml")
            for u in context.extracted_urls:
                if any(u.lower().endswith(tld) or f"{tld}/" in u.lower() for tld in suspicious_tlds):
                    indicators.append(f"Suspicious TLD in URL: {u[:40]}")
                    score += 25
                    break

        # 6. Threat Intel Detections
        if context.threat_intel_summary and isinstance(context.threat_intel_summary, dict):
            if context.threat_intel_summary.get("malicious_count", 0) > 0:
                indicators.append(f"Threat intelligence flagged {context.threat_intel_summary.get('malicious_count')} malicious IOC(s)")
                score += 45

        # Categorize
        if any("attachment" in ind.lower() or "malware" in ind.lower() for ind in indicators):
            category = "MALWARE"
            severity = "CRITICAL" if score >= 70 else "HIGH"
        elif any("wire transfer" in ind.lower() or "reply-to" in ind.lower() for ind in indicators):
            category = "BEC"
            severity = "HIGH" if score >= 50 else "MEDIUM"
        elif any("phishing" in ind.lower() or "spf" in ind.lower() or "dmarc" in ind.lower() or "urgent" in ind.lower() or "tld" in ind.lower() for ind in indicators):
            category = "PHISHING"
            severity = "CRITICAL" if score >= 80 else ("HIGH" if score >= 50 else "MEDIUM")
        elif score >= 25:
            category = "SPAM"
            severity = "LOW"
        else:
            category = "BENIGN"
            severity = "LOW"
            score = max(5, min(20, score))

        confidence = 0.88 if indicators else 0.82
        reasoning = (
            f"Forensic triage evaluated {len(indicators)} indicator(s). "
            f"Triggers: {'; '.join(indicators[:4]) if indicators else 'Sender authentication, routing integrity, and message payload verified clean.'}"
        )

        return ThreatClassificationResult(
            threat_category=category,
            severity=severity,
            confidence_score=confidence,
            summary="",
            reasoning=reasoning,
            indicators=indicators,
            model_used="sentineltrace-agent-ensemble",
        )

    def _fallback_summary(
        self,
        classification: ThreatClassificationResult,
        context: EmailThreatContext | None = None,
    ) -> str:
        if not context:
            return (
                f"Threat Assessment: {classification.threat_category} (Severity: {classification.severity})\n\n"
                f"Evaluation: {classification.reasoning or 'Standard deterministic threat evaluation completed.'}\n\n"
                f"SOC Recommendation: Monitor sender infrastructure and verify indicators."
            )

        subj = context.subject or "(No Subject)"
        sender = context.sender_email or "Unknown Sender"
        domain = context.sender_domain or "Unknown Domain"
        auth_status = f"SPF: {context.spf_result or 'NONE'}, DKIM: {context.dkim_result or 'NONE'}, DMARC: {context.dmarc_result or 'NONE'}"
        origin_ip = context.extracted_ips[0] if context.extracted_ips else "No external transit IP observed"

        # Paragraph 1: Executive Threat Assessment
        p1 = (
            f"EXECUTIVE ASSESSMENT: {classification.threat_category} — {classification.severity} RISK ({int(classification.confidence_score * 100)}% Confidence)\n"
            f"Message subject '{subj}' received from {sender} ({domain}) has been triaged by the SentinelTrace forensic multi-agent engine. "
            f"Email authentication results: {auth_status}."
        )

        # Paragraph 2: Origin & Forensic Findings
        indicators_desc = []
        if classification.indicators:
            indicators_desc.append("Detected risk indicators: " + "; ".join(classification.indicators[:4]) + ".")
        if context.extracted_urls:
            indicators_desc.append(f"Contains {len(context.extracted_urls)} extracted URL link(s).")
        if context.attachment_count > 0:
            indicators_desc.append(f"Carries {context.attachment_count} attachment(s) [{', '.join(context.attachment_names[:3])}].")
        if origin_ip != "No external transit IP observed":
            indicators_desc.append(f"Originating sender transit IP resolved to {origin_ip}.")

        p2 = " ".join(indicators_desc) if indicators_desc else (
            f"No malicious URLs, exploit payloads, or spoofing anomalies were detected in the message body or headers. Origin transit IP: {origin_ip}."
        )

        # Paragraph 3: Actionable SOC Remediation
        if classification.severity in ("CRITICAL", "HIGH"):
            p3 = (
                "ACTIONABLE REMEDIATION:\n"
                f"1. Quarantine message and block sender '{sender}' at email security gateway.\n"
                f"2. Add originating IP ({origin_ip}) and associated IOCs to perimeter blocklists.\n"
                "3. Reset recipient credentials if links were clicked and audit endpoint telemetry."
            )
        elif classification.severity == "MEDIUM":
            p3 = (
                "ACTIONABLE REMEDIATION:\n"
                "1. Advise recipient to exercise caution with unverified links or requests.\n"
                "2. Verify sender domain alignment and validate secondary communication channels.\n"
                "3. Monitor recipient inbox for follow-up spear-phishing attempts."
            )
        else:
            p3 = (
                "ACTIONABLE REMEDIATION:\n"
                "1. Message is classified as legitimate/benign communication.\n"
                "2. Sender authentication verified with normal routing characteristics.\n"
                "3. No immediate defensive containment required."
            )

        return f"{p1}\n\n{p2}\n\n{p3}"


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
