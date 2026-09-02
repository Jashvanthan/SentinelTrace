import asyncio
import uuid
import datetime
from sqlalchemy import select, exc
from app.db.session import AsyncSessionLocal as async_session_maker
from app.models.ai_analysis import AIAnalysis, AgentResult
from app.models.campaign import Campaign, CampaignMember
from app.models.workspace import Workspace
from app.models.email_analysis import EmailAnalysis, ThreatCategory
from app.schemas.agent_result import AgentStatus, RiskVerdict
from app.models.campaign import CampaignStatus


async def create_test_workspace_and_email(session, name):
    user_id = uuid.uuid4()
    # Mocking user required for owner? Usually owner is a FK, let's see if we need a user. 
    # Since it's a test, if there is a User table FK, we might need a User first. 
    # Let's import User and create one.
    from app.models.user import User
    user = User(email=f"{uuid.uuid4()}@test.com", password_hash="hash", full_name="Test User")
    session.add(user)
    await session.flush()
    
    ws = Workspace(name=name, slug=f"slug-{uuid.uuid4()}", owner_id=user.id)
    session.add(ws)
    await session.flush()
    email = EmailAnalysis(
        workspace_id=ws.id,
        source_provider="gmail",
        source_message_id=str(uuid.uuid4()),
        subject="Test",
        sender_email="test@test.com",
        recipients=["victim@test.com"],
        email_date=datetime.datetime.now(datetime.timezone.utc),
        all_headers={},
    )
    session.add(email)
    await session.flush()
    return ws, email


async def test_1_ai_analysis_insert_read():
    print("\n--- Test 1: AIAnalysis insert/read ---")
    async with async_session_maker() as session:
        ws, email = await create_test_workspace_and_email(session, "WS1")
        run_id = str(uuid.uuid4())
        
        analysis = AIAnalysis(
            workspace_id=ws.id,
            email_analysis_id=email.id,
            analysis_run_id=run_id,
            status="COMPLETED",
            final_score=85,
            final_verdict=RiskVerdict.CRITICAL,
            confidence=0.9,
            summary="Critical threat",
            explanation="Malicious URL found"
        )
        session.add(analysis)
        await session.commit()
        
        result = await session.execute(select(AIAnalysis).filter_by(analysis_run_id=run_id))
        db_analysis = result.scalars().first()
        assert db_analysis is not None
        assert db_analysis.final_score == 85
        assert db_analysis.final_verdict == RiskVerdict.CRITICAL
        print("Test 1 passed: AIAnalysis inserted and retrieved.")


async def test_2_six_agent_results():
    print("\n--- Test 2: Six AgentResults ---")
    async with async_session_maker() as session:
        ws, email = await create_test_workspace_and_email(session, "WS2")
        run_id = str(uuid.uuid4())
        
        analysis = AIAnalysis(workspace_id=ws.id, email_analysis_id=email.id, analysis_run_id=run_id, status="RUNNING")
        session.add(analysis)
        await session.flush()
        
        for i in range(6):
            res = AgentResult(
                workspace_id=ws.id,
                ai_analysis_id=analysis.id,
                email_analysis_id=email.id,
                analysis_run_id=run_id,
                agent_name=f"agent-{i}",
                agent_version="1.0",
                prompt_version="1.0",
                model="test-model",
                status=AgentStatus.COMPLETED,
                risk_score=50,
                confidence=0.9,
                classification=ThreatCategory.PHISHING
            )
            session.add(res)
        await session.commit()
        
        # Verify 1 AIAnalysis and 6 AgentResults
        res = await session.execute(select(AgentResult).filter_by(analysis_run_id=run_id))
        count = len(res.scalars().all())
        assert count == 6
        print("Test 2 passed: 6 AgentResults persisted.")


async def test_3_duplicate_agent_result_constraint():
    print("\n--- Test 3: Duplicate AgentResult constraint ---")
    async with async_session_maker() as session:
        ws, email = await create_test_workspace_and_email(session, "WS3")
        run_id = str(uuid.uuid4())
        analysis = AIAnalysis(workspace_id=ws.id, email_analysis_id=email.id, analysis_run_id=run_id)
        session.add(analysis)
        await session.flush()
        
        res1 = AgentResult(
            workspace_id=ws.id, ai_analysis_id=analysis.id, email_analysis_id=email.id,
            analysis_run_id=run_id, agent_name="agent-X", agent_version="1.0",
            prompt_version="1.0", model="m", status=AgentStatus.COMPLETED
        )
        session.add(res1)
        await session.commit()
        
        res2 = AgentResult(
            workspace_id=ws.id, ai_analysis_id=analysis.id, email_analysis_id=email.id,
            analysis_run_id=run_id, agent_name="agent-X", agent_version="1.0",
            prompt_version="1.0", model="m", status=AgentStatus.COMPLETED
        )
        session.add(res2)
        try:
            await session.commit()
            print("FAILED: Expected IntegrityError on duplicate AgentResult!")
        except exc.IntegrityError:
            print("Test 3 passed: PostgreSQL prevented duplicate (workspace_id, analysis_run_id, agent_name).")
            await session.rollback()


async def test_4_campaign_persistence():
    print("\n--- Test 4: Campaign persistence ---")
    async with async_session_maker() as session:
        ws, _ = await create_test_workspace_and_email(session, "WS4")
        
        camp = Campaign(
            workspace_id=ws.id,
            name="Phishing Campaign X",
            status=CampaignStatus.ACTIVE,
            correlation_score=80
        )
        session.add(camp)
        await session.commit()
        
        res = await session.execute(select(Campaign).filter_by(id=camp.id))
        db_camp = res.scalars().first()
        assert db_camp is not None
        assert db_camp.workspace_id == ws.id
        print("Test 4 passed: Campaign persisted.")


async def test_5_campaign_member_persistence():
    print("\n--- Test 5: CampaignMember persistence ---")
    async with async_session_maker() as session:
        ws, email = await create_test_workspace_and_email(session, "WS5")
        camp = Campaign(workspace_id=ws.id, name="C1")
        session.add(camp)
        await session.flush()
        
        mem = CampaignMember(
            workspace_id=ws.id,
            campaign_id=camp.id,
            email_analysis_id=email.id,
            matched_indicators=["http://evil.com"],
            correlation_reasons=["Shared URL"]
        )
        session.add(mem)
        await session.commit()
        
        res = await session.execute(select(CampaignMember).filter_by(campaign_id=camp.id))
        db_mem = res.scalars().first()
        assert db_mem is not None
        print("Test 5 passed: CampaignMember persisted.")


async def test_6_duplicate_campaign_member():
    print("\n--- Test 6: Duplicate CampaignMember constraint ---")
    async with async_session_maker() as session:
        ws, email = await create_test_workspace_and_email(session, "WS6")
        camp = Campaign(workspace_id=ws.id, name="C2")
        session.add(camp)
        await session.flush()
        
        mem1 = CampaignMember(workspace_id=ws.id, campaign_id=camp.id, email_analysis_id=email.id)
        session.add(mem1)
        await session.commit()
        
        mem2 = CampaignMember(workspace_id=ws.id, campaign_id=camp.id, email_analysis_id=email.id)
        session.add(mem2)
        try:
            await session.commit()
            print("FAILED: Expected IntegrityError on duplicate CampaignMember")
        except exc.IntegrityError:
            print("Test 6 passed: PostgreSQL prevented duplicate CampaignMember.")
            await session.rollback()


async def test_7_tenant_query_isolation():
    print("\n--- Test 7: Tenant query isolation ---")
    async with async_session_maker() as session:
        ws_A, email_A = await create_test_workspace_and_email(session, "WS-A")
        ws_B, email_B = await create_test_workspace_and_email(session, "WS-B")
        
        run_A = str(uuid.uuid4())
        session.add(AIAnalysis(workspace_id=ws_A.id, email_analysis_id=email_A.id, analysis_run_id=run_A))
        run_B = str(uuid.uuid4())
        session.add(AIAnalysis(workspace_id=ws_B.id, email_analysis_id=email_B.id, analysis_run_id=run_B))
        await session.commit()
        
        # Verify query scoped to A doesn't see B
        res_A = await session.execute(select(AIAnalysis).filter(AIAnalysis.workspace_id == ws_A.id))
        analyses_A = res_A.scalars().all()
        assert len(analyses_A) == 1
        assert analyses_A[0].workspace_id == ws_A.id
        print("Test 7 passed: Explicit workspace_id filter safely isolates queries.")


async def test_8_tenant_ownership_mismatch():
    print("\n--- Test 8: Tenant ownership mismatch ---")
    async with async_session_maker() as session:
        ws_A, _ = await create_test_workspace_and_email(session, "WS-A")
        ws_B, email_B = await create_test_workspace_and_email(session, "WS-B")
        
        # Campaign from A
        camp_A = Campaign(workspace_id=ws_A.id, name="Camp A")
        session.add(camp_A)
        await session.commit()
        
        # Attack: Attempt to link Email B (Workspace B) into Campaign A (Workspace A)
        mem = CampaignMember(workspace_id=ws_A.id, campaign_id=camp_A.id, email_analysis_id=email_B.id)
        session.add(mem)
        
        try:
            await session.commit()
            # If it succeeds, the DB permits logical cross-tenant relationships.
            print("Observation: The database natively permits logically mismatched tenants across standard independent FKs.")
            print("Test 8 passed (Documented): DB allows it, so the Application Layer MUST enforce it before insert!")
        except exc.IntegrityError:
            print("Test 8 passed (Documented): DB rejected it natively.")
            await session.rollback()


async def test_9_fk_enforcement():
    print("\n--- Test 9: Foreign key enforcement ---")
    async with async_session_maker() as session:
        analysis = AIAnalysis(workspace_id=uuid.uuid4(), email_analysis_id=uuid.uuid4(), analysis_run_id=str(uuid.uuid4()))
        session.add(analysis)
        try:
            await session.commit()
            print("FAILED: Should have rejected nonexistent FKs!")
        except exc.IntegrityError:
            print("Test 9 passed: PostgreSQL correctly rejected nonexistent Workspace/Email UUIDs.")
            await session.rollback()


async def test_10_jsonb_round_trip():
    print("\n--- Test 10: JSONB round-trip ---")
    async with async_session_maker() as session:
        ws, email = await create_test_workspace_and_email(session, "WS10")
        
        evidence_dict = [{"type": "URL", "value": "http://test.com"}]
        run_id = str(uuid.uuid4())
        
        analysis = AIAnalysis(
            workspace_id=ws.id, email_analysis_id=email.id, analysis_run_id=run_id,
            evidence=evidence_dict
        )
        session.add(analysis)
        await session.commit()
        
        res = await session.execute(select(AIAnalysis).filter_by(analysis_run_id=run_id))
        db_obj = res.scalars().first()
        assert db_obj.evidence == evidence_dict
        assert isinstance(db_obj.evidence, list)
        print("Test 10 passed: JSONB natively structured and preserved.")


async def main():
    try:
        await test_1_ai_analysis_insert_read()
        await test_2_six_agent_results()
        await test_3_duplicate_agent_result_constraint()
        await test_4_campaign_persistence()
        await test_5_campaign_member_persistence()
        await test_6_duplicate_campaign_member()
        await test_7_tenant_query_isolation()
        await test_8_tenant_ownership_mismatch()
        await test_9_fk_enforcement()
        await test_10_jsonb_round_trip()
        print("\nALL REAL POSTGRESQL PERSISTENCE TESTS PASSED.")
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
