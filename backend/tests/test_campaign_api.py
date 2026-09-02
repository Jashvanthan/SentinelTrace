import uuid
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select, func

from app.main import app
from app.db.session import get_db_session
from app.models.campaign import Campaign, CampaignMember
from app.models.email_analysis import EmailAnalysis
from app.models.audit_log import AuditLog

@pytest.fixture
async def test_env():
    """Sets up User A with Workspace A, and User B with Workspace B, plus sample EmailAnalyses."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Create User A & Workspace A
        await ac.post("/api/v1/auth/register", json={"email": "usera_camp@test.com", "password": "SuperSecretPassword123", "full_name": "User A"})
        resp_a = await ac.post("/api/v1/auth/login", json={"email": "usera_camp@test.com", "password": "SuperSecretPassword123"})
        token_a = resp_a.json()["access_token"]
        resp_ws_a = await ac.post("/api/v1/workspaces", json={"name": "Workspace A"}, headers={"Authorization": f"Bearer {token_a}"})
        ws_a_id = resp_ws_a.json()["id"]

        # Create User B & Workspace B
        await ac.post("/api/v1/auth/register", json={"email": "userb_camp@test.com", "password": "SuperSecretPassword123", "full_name": "User B"})
        resp_b = await ac.post("/api/v1/auth/login", json={"email": "userb_camp@test.com", "password": "SuperSecretPassword123"})
        token_b = resp_b.json()["access_token"]
        resp_ws_b = await ac.post("/api/v1/workspaces", json={"name": "Workspace B"}, headers={"Authorization": f"Bearer {token_b}"})
        ws_b_id = resp_ws_b.json()["id"]

        # Seed Database with EmailAnalysis records directly
        async for session in get_db_session():
            ea_a = EmailAnalysis(workspace_id=uuid.UUID(ws_a_id), subject="Phish A", sender_email="attacker@evil.com", message_id="msgA", status="COMPLETE")
            ea_b = EmailAnalysis(workspace_id=uuid.UUID(ws_b_id), subject="Phish B", sender_email="attacker@evil.com", message_id="msgB", status="COMPLETE")
            session.add_all([ea_a, ea_b])
            await session.commit()
            ea_a_id = ea_a.id
            ea_b_id = ea_b.id
            break

        return {
            "token_a": token_a,
            "ws_a_id": ws_a_id,
            "ea_a_id": str(ea_a_id),
            "token_b": token_b,
            "ws_b_id": ws_b_id,
            "ea_b_id": str(ea_b_id)
        }


@pytest.mark.asyncio
async def test_campaign_api_unauthenticated(test_env):
    """Verify endpoints reject unauthenticated users."""
    ws_a_id = test_env["ws_a_id"]
    ea_a_id = test_env["ea_a_id"]
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post(f"/api/v1/workspaces/{ws_a_id}/campaigns/correlate/{ea_a_id}")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_campaign_correlation_success_and_idempotency(test_env):
    """Verify correlation creates campaigns/members idempotently and logs the action."""
    token_a = test_env["token_a"]
    ws_a_id = test_env["ws_a_id"]
    ea_a_id = test_env["ea_a_id"]
    headers = {"Authorization": f"Bearer {token_a}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # First correlation call
        resp1 = await ac.post(f"/api/v1/workspaces/{ws_a_id}/campaigns/correlate/{ea_a_id}", headers=headers)
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["email_analysis_id"] == ea_a_id
        
        # In a real environment with mocked data, it might return empty campaigns or newly generated ones
        # We will check the database count to ensure it doesn't duplicate on second call.
        async for session in get_db_session():
            campaign_count_1 = await session.scalar(select(func.count()).select_from(Campaign).where(Campaign.workspace_id == uuid.UUID(ws_a_id)))
            member_count_1 = await session.scalar(select(func.count()).select_from(CampaignMember).where(CampaignMember.workspace_id == uuid.UUID(ws_a_id)))
            
            # Verify Audit Log
            audit = await session.scalar(select(AuditLog).where(AuditLog.action == "CAMPAIGN_CORRELATION_TRIGGERED"))
            assert audit is not None
            # Ensure no secrets in details
            if audit.details:
                assert "password" not in audit.details
            break
            
        # Second correlation call
        resp2 = await ac.post(f"/api/v1/workspaces/{ws_a_id}/campaigns/correlate/{ea_a_id}", headers=headers)
        assert resp2.status_code == 200
        
        async for session in get_db_session():
            campaign_count_2 = await session.scalar(select(func.count()).select_from(Campaign).where(Campaign.workspace_id == uuid.UUID(ws_a_id)))
            member_count_2 = await session.scalar(select(func.count()).select_from(CampaignMember).where(CampaignMember.workspace_id == uuid.UUID(ws_a_id)))
            break
            
        # Idempotency check: counts should not increase
        assert campaign_count_1 == campaign_count_2
        assert member_count_1 == member_count_2


@pytest.mark.asyncio
async def test_campaign_cross_workspace_isolation(test_env):
    """
    ATTACKS 1-4: Ensure Workspace A user cannot access Workspace B campaigns or emails.
    """
    token_a = test_env["token_a"]
    ws_b_id = test_env["ws_b_id"]
    ea_b_id = test_env["ea_b_id"]
    headers = {"Authorization": f"Bearer {token_a}"}
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Attack 1: User A tries to trigger correlation using Workspace B's ID in URL
        resp_corr = await ac.post(f"/api/v1/workspaces/{ws_b_id}/campaigns/correlate/{ea_b_id}", headers=headers)
        assert resp_corr.status_code == 404  # WorkspaceMember check fails

        # Attack 2: User A tries to trigger correlation using their own WS ID but B's email analysis
        ws_a_id = test_env["ws_a_id"]
        resp_corr_email = await ac.post(f"/api/v1/workspaces/{ws_a_id}/campaigns/correlate/{ea_b_id}", headers=headers)
        assert resp_corr_email.status_code == 404  # Email not found in this workspace

        # Attack 3: List campaigns for WS B
        resp_list = await ac.get(f"/api/v1/workspaces/{ws_b_id}/campaigns", headers=headers)
        assert resp_list.status_code == 404

        # Attack 4: Get specific campaign belonging to WS B
        # Let's assume a random UUID for campaign_id (even if it existed, they would get 404 for WS B)
        fake_camp_id = str(uuid.uuid4())
        resp_get = await ac.get(f"/api/v1/workspaces/{ws_b_id}/campaigns/{fake_camp_id}", headers=headers)
        assert resp_get.status_code == 404
        
        # Get members of a campaign
        resp_members = await ac.get(f"/api/v1/workspaces/{ws_b_id}/campaigns/{fake_camp_id}/members", headers=headers)
        assert resp_members.status_code == 404

        # Verify no unauthorized audit logs were leaked/bypassed
        async for session in get_db_session():
            audit = await session.scalar(select(AuditLog).where(AuditLog.action == "CORRELATION_ATTEMPT_DENIED"))
            assert audit is not None
            assert audit.outcome == "FAILURE"
            break
