import asyncio
import uuid
from typing import Dict

from app.schemas.agent_result import (
    RiskVerdict,
    AgentExecutionResult,
    AgentStatus,
    ThreatCategory,
    AgentFinding,
    FindingSeverity
)
from app.services.risk_fusion_service import RiskFusionService

def make_agent_result(name: str, score: int, status: AgentStatus = AgentStatus.COMPLETED) -> AgentExecutionResult:
    return AgentExecutionResult(
        workspace_id=uuid.uuid4(),
        email_analysis_id=uuid.uuid4(),
        agent_name=name,
        agent_version="1.0",
        prompt_version="1.0",
        model="test-model",
        status=status,
        risk_score=score,
        classification=ThreatCategory.BENIGN if score < 20 else ThreatCategory.SPAM,
    )

async def test_1_benign():
    print("Test 1: Benign...")
    fusion = RiskFusionService()
    det_ev = {}
    agents = {
        "email_nlp": make_agent_result("email_nlp", 10),
        "url_domain": make_agent_result("url_domain", 5),
    }
    result = fusion.fuse(det_ev, agents)
    assert result.verdict == RiskVerdict.BENIGN
    assert result.risk_score < 20
    print("Test 1 passed.")

async def test_2_single_malicious_url():
    print("Test 2: Single malicious URL...")
    fusion = RiskFusionService()
    det_ev = {"malicious_url": True}
    agents = {
        "url_domain": make_agent_result("url_domain", 80),
    }
    result = fusion.fuse(det_ev, agents)
    assert result.verdict in (RiskVerdict.HIGH_RISK, RiskVerdict.CRITICAL)
    print("Test 2 passed.")

async def test_3_malicious_attachment():
    print("Test 3: Malicious attachment...")
    fusion = RiskFusionService()
    det_ev = {"malicious_attachment": True}
    agents = {}
    result = fusion.fuse(det_ev, agents)
    assert result.verdict == RiskVerdict.CRITICAL
    assert result.risk_score >= 80
    print("Test 3 passed.")

async def test_4_multiple_indicators():
    print("Test 4: Multiple independent malicious indicators...")
    fusion = RiskFusionService()
    det_ev = {
        "malicious_url": True,
        "malicious_attachment": True,
        "malicious_sender_ip": True
    }
    agents = {}
    result = fusion.fuse(det_ev, agents)
    assert result.verdict == RiskVerdict.CRITICAL
    assert result.risk_score >= 80
    print("Test 4 passed.")

async def test_5_weak_ai_suspicion():
    print("Test 5: Weak AI suspicion only...")
    fusion = RiskFusionService()
    det_ev = {}
    agents = {
        "email_nlp": make_agent_result("email_nlp", 70), # Suspicious/High risk
    }
    result = fusion.fuse(det_ev, agents)
    assert result.verdict not in (RiskVerdict.HIGH_RISK, RiskVerdict.CRITICAL)
    print("Test 5 passed.")

async def test_6_conflicting_agents():
    print("Test 6: Conflicting agents...")
    fusion = RiskFusionService()
    det_ev = {"malicious_url": True}
    agents = {
        "url_domain": make_agent_result("url_domain", 85),
        "email_nlp": make_agent_result("email_nlp", 10),
    }
    result = fusion.fuse(det_ev, agents)
    assert "email_nlp" in result.conflicting_agents
    assert result.confidence < 1.0 # Decreased confidence
    print("Test 6 passed.")

async def test_7_missing_agents():
    print("Test 7: Missing agents...")
    fusion = RiskFusionService()
    det_ev = {}
    agents = {
        "url_domain": make_agent_result("url_domain", 10),
        "email_nlp": make_agent_result("email_nlp", 0, AgentStatus.FAILED),
        "sender_ip": make_agent_result("sender_ip", 0, AgentStatus.TIMEOUT),
    }
    result = fusion.fuse(det_ev, agents)
    assert result.confidence < 0.95
    print("Test 7 passed.")

async def test_8_unknown_intelligence():
    print("Test 8: Unknown intelligence...")
    fusion = RiskFusionService()
    det_ev = {} # nothing triggers malicious
    agents = {}
    result = fusion.fuse(det_ev, agents)
    assert result.verdict == RiskVerdict.BENIGN
    print("Test 8 passed.")

async def test_9_geoip_only():
    print("Test 9: GeoIP only...")
    fusion = RiskFusionService()
    det_ev = {"geoip_russia": True} # not a mapped malicious field
    agents = {}
    result = fusion.fuse(det_ev, agents)
    assert result.verdict == RiskVerdict.BENIGN
    print("Test 9 passed.")

async def test_10_score_boundaries():
    print("Test 10: Score boundaries...")
    fusion = RiskFusionService()
    assert fusion.score_to_verdict(19) == RiskVerdict.BENIGN
    assert fusion.score_to_verdict(20) == RiskVerdict.SUSPICIOUS
    assert fusion.score_to_verdict(39) == RiskVerdict.SUSPICIOUS
    assert fusion.score_to_verdict(40) == RiskVerdict.MEDIUM_RISK
    assert fusion.score_to_verdict(59) == RiskVerdict.MEDIUM_RISK
    assert fusion.score_to_verdict(60) == RiskVerdict.HIGH_RISK
    assert fusion.score_to_verdict(79) == RiskVerdict.HIGH_RISK
    assert fusion.score_to_verdict(80) == RiskVerdict.CRITICAL
    assert fusion.score_to_verdict(100) == RiskVerdict.CRITICAL
    print("Test 10 passed.")

async def test_11_provenance():
    print("Test 11: Provenance...")
    fusion = RiskFusionService()
    det_ev = {"malicious_url": True}
    agents = {
        "url_domain": make_agent_result("url_domain", 80),
    }
    result = fusion.fuse(det_ev, agents)
    source_types = [ev.source_type for ev in result.evidence]
    assert "deterministic" in source_types
    assert "agent" in source_types
    print("Test 11 passed.")

async def test_12_malformed_agent_result():
    print("Test 12: Malformed agent result...")
    fusion = RiskFusionService()
    det_ev = {}
    malformed = make_agent_result("url_domain", 0, AgentStatus.FAILED)
    malformed.risk_score = None # Missing score safely handled
    agents = {"url_domain": malformed}
    result = fusion.fuse(det_ev, agents)
    assert "url_domain" not in result.contributing_agents
    print("Test 12 passed.")

async def test_13_prompt_injection_regression():
    print("Test 13: Prompt injection regression...")
    fusion = RiskFusionService()
    det_ev = {}
    agents = {
        "email_nlp": make_agent_result("email_nlp", 99),
    }
    result = fusion.fuse(det_ev, agents)
    assert result.verdict != RiskVerdict.CRITICAL # AI alone cannot force critical override logic
    print("Test 13 passed.")

async def main():
    try:
        await test_1_benign()
        await test_2_single_malicious_url()
        await test_3_malicious_attachment()
        await test_4_multiple_indicators()
        await test_5_weak_ai_suspicion()
        await test_6_conflicting_agents()
        await test_7_missing_agents()
        await test_8_unknown_intelligence()
        await test_9_geoip_only()
        await test_10_score_boundaries()
        await test_11_provenance()
        await test_12_malformed_agent_result()
        await test_13_prompt_injection_regression()
        print("ALL FUSION TESTS PASSED")
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
