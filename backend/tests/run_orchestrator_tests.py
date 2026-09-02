import asyncio
import uuid
from unittest.mock import AsyncMock, patch, MagicMock

from app.models.email_analysis import EmailAnalysis, ThreatCategory
from app.schemas.agent_result import BaseAgentResponse, AgentStatus, AgentFinding, FindingSeverity
from app.services.agent_orchestrator import AgentOrchestrator, OrchestrationError, LLMProviderError

async def mock_execute_success(*args, **kwargs):
    return BaseAgentResponse(
        risk_score=5,
        confidence=0.9,
        classification=ThreatCategory.BENIGN,
        findings=[],
        evidence=[],
        recommendations=[]
    )

async def test_successful_orchestration():
    print("Testing successful orchestration...")
    orchestrator = AgentOrchestrator()
    workspace_id = uuid.uuid4()
    email_analysis_id = uuid.uuid4()
    
    mock_db = AsyncMock()
    mock_analysis = EmailAnalysis(
        id=email_analysis_id,
        workspace_id=workspace_id,
        sender_email="test@test.com",
        sender_display_name="Test",
        sender_domain="test.com",
        ai_summary="Email body",
    )
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_analysis
    mock_db.execute.return_value = mock_result
    
    with patch("app.agents.base_agent.get_ai_service") as mock_get_service:
        mock_service = AsyncMock()
        mock_service.execute_agent.side_effect = mock_execute_success
        mock_get_service.return_value = mock_service
        
        result = await orchestrator.orchestrate(mock_db, workspace_id, email_analysis_id, "run-123")
        assert result["status"] == "COMPLETED"
        for agent, status in result["agents"].items():
            assert status == "COMPLETED"
        print("Successful orchestration passed.")

async def test_partial_failure():
    print("Testing partial failure...")
    orchestrator = AgentOrchestrator()
    workspace_id = uuid.uuid4()
    email_analysis_id = uuid.uuid4()
    
    mock_db = AsyncMock()
    mock_analysis = EmailAnalysis(
        id=email_analysis_id,
        workspace_id=workspace_id,
        sender_email="test@test.com",
        sender_display_name="Test"
    )
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_analysis
    mock_db.execute.return_value = mock_result
    
    # Let url_domain fail with a ValueError
    async def mock_execute_partial_fail(system_prompt, *args, **kwargs):
        if "URL/Domain" in system_prompt:
            raise ValueError("Malformed output validation failed")
        return await mock_execute_success(*args, **kwargs)
        
    with patch("app.agents.base_agent.get_ai_service") as mock_get_service:
        mock_service = AsyncMock()
        mock_service.execute_agent.side_effect = mock_execute_partial_fail
        mock_get_service.return_value = mock_service
        
        result = await orchestrator.orchestrate(mock_db, workspace_id, email_analysis_id, "run-123")
        assert result["status"] == "COMPLETED"
        assert result["agents"]["url_domain"] == "FAILED"
        assert result["agents"]["email_nlp"] == "COMPLETED"
        print("Partial failure passed.")

async def test_workspace_isolation():
    print("Testing workspace isolation...")
    orchestrator = AgentOrchestrator()
    workspace_id = uuid.uuid4()
    email_analysis_id = uuid.uuid4()
    
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_result
    
    try:
        await orchestrator.orchestrate(mock_db, workspace_id, email_analysis_id, "run-123")
        assert False, "Should raise OrchestrationError"
    except OrchestrationError:
        print("Workspace isolation passed.")

async def test_context_window_protection():
    print("Testing context window protection...")
    orchestrator = AgentOrchestrator()
    workspace_id = uuid.uuid4()
    email_analysis_id = uuid.uuid4()
    
    mock_db = AsyncMock()
    mock_analysis = EmailAnalysis(
        id=email_analysis_id,
        workspace_id=workspace_id,
        sender_email="test@test.com",
        sender_display_name="Test"
    )
    # Inject 100 urls
    mock_analysis.extracted_urls = [f"http://test.com/{i}" for i in range(100)]
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_analysis
    mock_db.execute.return_value = mock_result
    
    with patch("app.agents.base_agent.get_ai_service") as mock_get_service:
        mock_service = AsyncMock()
        mock_service.execute_agent.side_effect = mock_execute_success
        mock_get_service.return_value = mock_service
        
        await orchestrator.orchestrate(mock_db, workspace_id, email_analysis_id, "run-123")
        
        # Verify that URL agent received only MAX_URLS (50)
        found_url_agent_call = False
        for call_args in mock_service.execute_agent.call_args_list:
            system_prompt = call_args.kwargs.get("system_prompt", "")
            if "URL/Domain" in system_prompt:
                found_url_agent_call = True
                assert len(call_args.kwargs["trusted_evidence"]["extracted_urls"]) == 50
        assert found_url_agent_call
        print("Context window protection passed.")

async def main():
    try:
        await test_successful_orchestration()
        await test_partial_failure()
        await test_workspace_isolation()
        await test_context_window_protection()
        print("ALL ORCHESTRATOR TESTS PASSED")
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
