"""
SentinelTrace Backend — Risk Fusion Service
"""
import logging
from typing import Dict, List, Tuple

from app.schemas.agent_result import (
    RiskFusionResponse,
    RiskVerdict,
    AgentExecutionResult,
    AgentStatus,
    EvidenceItem
)


logger = logging.getLogger(__name__)

class RiskFusionService:
    """
    Deterministic engine that combines raw forensic evidence with AI agent results 
    to produce a final, explainable threat assessment.
    """
    
    @staticmethod
    def score_to_verdict(score: int) -> RiskVerdict:
        """Map a 0-100 score strictly to a 5-level verdict."""
        if score <= 19:
            return RiskVerdict.BENIGN
        elif score <= 39:
            return RiskVerdict.SUSPICIOUS
        elif score <= 59:
            return RiskVerdict.MEDIUM_RISK
        elif score <= 79:
            return RiskVerdict.HIGH_RISK
        else:
            return RiskVerdict.CRITICAL

    def fuse(
        self,
        deterministic_evidence: Dict[str, bool],
        agent_results: Dict[str, AgentExecutionResult],
    ) -> RiskFusionResponse:
        
        score = 0
        evidence_items: List[EvidenceItem] = []
        indicators: List[str] = []
        
        # 1. Deterministic Evidence Processing
        if deterministic_evidence.get("malicious_attachment"):
            score += 35
            indicators.append("malicious_attachment")
            evidence_items.append(EvidenceItem(
                source_type="deterministic",
                source="attachment_analyzer",
                description="Confirmed malicious attachment hash detected."
            ))
            
        if deterministic_evidence.get("malicious_url"):
            score += 30
            indicators.append("malicious_url")
            evidence_items.append(EvidenceItem(
                source_type="deterministic",
                source="url_analyzer",
                description="Confirmed malicious URL detected."
            ))
            
        if deterministic_evidence.get("malicious_ioc"):
            score += 35
            indicators.append("malicious_ioc")
            evidence_items.append(EvidenceItem(
                source_type="deterministic",
                source="threat_intel",
                description="Confirmed malicious indicator of compromise (IOC) matched."
            ))
            
        if deterministic_evidence.get("malicious_sender_ip"):
            score += 25
            indicators.append("malicious_sender_ip")
            evidence_items.append(EvidenceItem(
                source_type="deterministic",
                source="ip_reputation",
                description="Sender IP has a known malicious reputation."
            ))
            
        if deterministic_evidence.get("auth_failure"):
            score += 15
            indicators.append("auth_failure")
            evidence_items.append(EvidenceItem(
                source_type="deterministic",
                source="auth_analyzer",
                description="Strong SPF/DKIM/DMARC authentication failure."
            ))
            
        if deterministic_evidence.get("suspicious_domain"):
            score += 10
            indicators.append("suspicious_domain")
            evidence_items.append(EvidenceItem(
                source_type="deterministic",
                source="domain_analyzer",
                description="Sender domain is newly registered or highly suspicious."
            ))

        # 2. AI Agent Processing
        contributing_agents = []
        high_risk_agents = []
        benign_agents = []
        total_completed = 0
        total_expected = len(agent_results)
        
        for name, result in agent_results.items():
            if result.status == AgentStatus.COMPLETED and result.risk_score is not None:
                total_completed += 1
                contributing_agents.append(name)
                
                agent_verdict = self.score_to_verdict(result.risk_score)
                if agent_verdict in (RiskVerdict.HIGH_RISK, RiskVerdict.CRITICAL):
                    high_risk_agents.append(name)
                    # Add AI finding as interpretation evidence
                    evidence_items.append(EvidenceItem(
                        source_type="agent",
                        source=name,
                        description=f"Agent assessed threat as {agent_verdict.value} (score {result.risk_score})."
                    ))
                elif agent_verdict == RiskVerdict.BENIGN:
                    benign_agents.append(name)
        
        # AI Agreement Scoring
        if len(high_risk_agents) >= 2:
            score += 15
            evidence_items.append(EvidenceItem(
                source_type="fused",
                source="risk_fusion_engine",
                description="Strong multi-agent agreement on high risk."
            ))
        elif len(high_risk_agents) == 1:
            score += 5
            evidence_items.append(EvidenceItem(
                source_type="fused",
                source="risk_fusion_engine",
                description="Isolated AI suspicion from a single agent."
            ))
            
        if len(benign_agents) >= 3 and score < 40 and not indicators:
            score -= 10  # Mitigating factor if many agents agree it's benign and no hard indicators exist
            
        # 3. Critical Evidence Overrides (Floors)
        if deterministic_evidence.get("malicious_attachment"):
            score = max(score, 80)
        elif deterministic_evidence.get("malicious_url") or deterministic_evidence.get("malicious_ioc"):
            score = max(score, 60)
            
        # Clamp score
        score = max(0, min(100, score))
        final_verdict = self.score_to_verdict(score)
        
        # 4. Conflicting Agents
        conflicting_agents = []
        if final_verdict in (RiskVerdict.HIGH_RISK, RiskVerdict.CRITICAL):
            conflicting_agents = benign_agents
        elif final_verdict in (RiskVerdict.BENIGN, RiskVerdict.SUSPICIOUS):
            conflicting_agents = high_risk_agents
            
        # 5. Confidence Calculation
        # Base confidence starts high, drops based on missing agents and conflicts
        confidence = 0.95
        
        # Missing agents penalty
        missing = total_expected - total_completed
        if total_expected > 0:
            confidence -= (missing / total_expected) * 0.2
            
        # Conflict penalty
        if conflicting_agents:
            confidence -= 0.15 * min(2, len(conflicting_agents))
            
        # Strong deterministic evidence boosts confidence back up
        if indicators and final_verdict in (RiskVerdict.HIGH_RISK, RiskVerdict.CRITICAL):
            confidence += 0.1
            
        confidence = max(0.0, min(1.0, round(confidence, 2)))
        
        # 6. Explanations
        key_findings = [f"Final Score: {score}"]
        if indicators:
            key_findings.append(f"Triggered deterministic rules: {', '.join(indicators)}")
        if high_risk_agents:
            key_findings.append(f"High risk AI alerts from: {', '.join(high_risk_agents)}")
            
        summary = f"Assessed as {final_verdict.value} (Score {score})."
        
        explanation_lines = [
            f"Final Verdict: {final_verdict.value}",
            f"Risk Score: {score}",
            f"Confidence: {confidence}",
            "",
            "Primary contributors:"
        ]
        
        for ev in evidence_items:
            if ev.source_type == "deterministic":
                explanation_lines.append(f"- {ev.description} [{ev.source}]")
        for ev in evidence_items:
            if ev.source_type == "fused":
                explanation_lines.append(f"- {ev.description}")
                
        if conflicting_agents:
            explanation_lines.append("")
            explanation_lines.append("Conflicting evidence:")
            explanation_lines.append(f"- Agents {', '.join(conflicting_agents)} disagreed with final severity.")
            
        if missing > 0:
            explanation_lines.append("")
            explanation_lines.append("Unavailable evidence:")
            missing_names = set(agent_results.keys()) - set(contributing_agents)
            explanation_lines.append(f"- Agent analysis unavailable for: {', '.join(missing_names)}")

        return RiskFusionResponse(
            risk_score=score,
            verdict=final_verdict,
            confidence=confidence,
            summary=summary,
            key_findings=key_findings,
            evidence=evidence_items,
            contributing_agents=contributing_agents,
            conflicting_agents=conflicting_agents,
            deterministic_indicators=indicators,
            explanation="\n".join(explanation_lines)
        )
