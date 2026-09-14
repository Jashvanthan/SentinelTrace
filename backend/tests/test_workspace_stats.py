"""
SentinelTrace Backend — Tests: Workspace Statistics Endpoint (Step 14)

Tests:
  1.  Member can retrieve own workspace stats (200)
  2.  Non-member is denied (404 — anti-enumeration)
  3.  Workspace A stats contain only Workspace A data
  4.  Empty workspace returns valid zero/null metrics without error
  5.  Risk score (average_threat_score / workspace_risk_score) calculation
  6.  Weekly high/critical IOC filtering (threshold >= 70, current week only)
  7.  BOLA regression: email list endpoint workspace isolation
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


# ── Helpers ────────────────────────────────────────────────────────────────────

async def _register_and_login(ac: AsyncClient, email: str, password: str, full_name: str) -> str:
    """Register a user and return their access token."""
    await ac.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password, "full_name": full_name},
    )
    resp = await ac.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert resp.status_code == 200, f"Login failed for {email}: {resp.text}"
    return resp.json()["access_token"]


async def _create_workspace(ac: AsyncClient, token: str, name: str) -> str:
    """Create a workspace and return its ID."""
    resp = await ac.post(
        "/api/v1/workspaces",
        json={"name": name},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201, f"Workspace creation failed: {resp.text}"
    return resp.json()["id"]


async def _insert_email(db, workspace_id: uuid.UUID, threat_score: float | None = None,
                         severity: str | None = None) -> uuid.UUID:
    """Directly insert a minimal EmailAnalysis for testing."""
    from app.models.email_analysis import AnalysisStatus, EmailAnalysis, SeverityLevel, ThreatCategory
    ea = EmailAnalysis(
        workspace_id=workspace_id,
        status=AnalysisStatus.COMPLETE,
        threat_score=threat_score,
        severity=SeverityLevel[severity] if severity else None,
        subject="Test email",
        sender_email="test@example.com",
        threat_category=ThreatCategory.PHISHING if severity and severity != "INFO" else ThreatCategory.BENIGN,
    )
    db.add(ea)
    await db.flush()
    return ea.id


async def _insert_ioc(db, workspace_id: uuid.UUID, analysis_id: uuid.UUID,
                       threat_score: int | None = None, days_ago: int = 0) -> None:
    """Directly insert an IOC for testing."""
    from datetime import UTC, datetime, timedelta
    from sqlalchemy import text
    from app.models.ioc import IOC, IOCType

    ioc = IOC(
        workspace_id=workspace_id,
        analysis_id=analysis_id,
        ioc_type=IOCType.IP_ADDRESS,
        value=f"10.0.0.{uuid.uuid4().int % 254 + 1}",
        threat_score=threat_score,
    )
    db.add(ioc)
    await db.flush()

    if days_ago > 0:
        # Move the created_at timestamp back
        past_dt = datetime.now(UTC) - timedelta(days=days_ago)
        await db.execute(
            text("UPDATE iocs SET created_at = :dt WHERE id = :id"),
            {"dt": past_dt, "id": ioc.id},
        )


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
async def two_users():
    """Fixture: two independent users, each owning their own workspace."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        token_a = await _register_and_login(ac, "stats_a@test.com", "SuperSecret123!", "Stats A")
        token_b = await _register_and_login(ac, "stats_b@test.com", "SuperSecret123!", "Stats B")
        ws_a = await _create_workspace(ac, token_a, "Stats Workspace A")
        ws_b = await _create_workspace(ac, token_b, "Stats Workspace B")
        return {
            "token_a": token_a,
            "token_b": token_b,
            "ws_a": ws_a,
            "ws_b": ws_b,
        }


# ── Test 1: Member can retrieve own workspace stats ────────────────────────────

@pytest.mark.asyncio
async def test_member_can_get_own_stats(two_users):
    """Authenticated workspace member receives 200 with valid stats."""
    token_a, ws_a = two_users["token_a"], two_users["ws_a"]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get(
            f"/api/v1/workspaces/{ws_a}/stats",
            headers={"Authorization": f"Bearer {token_a}"},
        )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "total_emails_scanned" in data
    assert "threats_detected" in data
    assert "active_campaigns" in data
    assert "workspace_risk_score" in data
    assert "average_threat_score" in data
    assert "high_critical_iocs_this_week" in data
    assert "ioc_type_distribution" in data
    assert "top_campaigns" in data
    assert "recent_emails" in data


# ── Test 2: Non-member is denied (404) ────────────────────────────────────────

@pytest.mark.asyncio
async def test_non_member_denied_404(two_users):
    """
    User B cannot access User A's workspace stats.
    Expected 404 — anti-enumeration (does not reveal whether workspace exists).
    """
    token_b, ws_a = two_users["token_b"], two_users["ws_a"]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get(
            f"/api/v1/workspaces/{ws_a}/stats",
            headers={"Authorization": f"Bearer {token_b}"},
        )
    assert resp.status_code == 404, (
        f"Expected 404 for non-member, got {resp.status_code}: {resp.text}"
    )


# ── Test 3: Workspace A stats contain only Workspace A data ───────────────────

@pytest.mark.asyncio
async def test_stats_are_workspace_scoped(two_users):
    """
    Emails and IOCs from Workspace B must NOT appear in Workspace A's stats.
    """
    ws_a_id = uuid.UUID(two_users["ws_a"])
    ws_b_id = uuid.UUID(two_users["ws_b"])

    from app.db.session import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        # Insert 3 emails in workspace A, 2 in workspace B
        for _ in range(3):
            await _insert_email(db, ws_a_id, threat_score=50.0, severity="HIGH")
        for _ in range(2):
            await _insert_email(db, ws_b_id, threat_score=80.0, severity="CRITICAL")
        await db.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get(
            f"/api/v1/workspaces/{two_users['ws_a']}/stats",
            headers={"Authorization": f"Bearer {two_users['token_a']}"},
        )

    assert resp.status_code == 200
    data = resp.json()
    # Workspace A should see exactly 3 emails
    assert data["total_emails_scanned"] == 3, (
        f"Expected 3 emails in workspace A, got {data['total_emails_scanned']}"
    )
    # Workspace B's CRITICAL emails must not inflate workspace A's threat count
    assert data["threats_detected"] == 3  # all 3 are HIGH


# ── Test 4: Empty workspace returns valid zero/null metrics ───────────────────

@pytest.mark.asyncio
async def test_empty_workspace_returns_zeros(two_users):
    """
    A workspace containing no analyses, campaigns, or IOCs must return a valid
    response with zero counts and null averages — no 500 errors.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get(
            f"/api/v1/workspaces/{two_users['ws_a']}/stats",
            headers={"Authorization": f"Bearer {two_users['token_a']}"},
        )

    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total_emails_scanned"] == 0
    assert data["threats_detected"] == 0
    assert data["active_campaigns"] == 0
    assert data["high_critical_iocs_this_week"] == 0
    assert data["ioc_type_distribution"] == {}
    assert data["top_campaigns"] == []
    assert data["recent_emails"] == []
    # Averages should be null for empty workspace
    assert data["average_threat_score"] is None
    assert data["workspace_risk_score"] is None


# ── Test 5: Risk score calculation ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_risk_score_calculation(two_users):
    """
    average_threat_score must equal AVG(threat_score) for workspace emails.
    workspace_risk_score must equal average_threat_score.
    """
    ws_id = uuid.UUID(two_users["ws_a"])

    from app.db.session import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        # Insert 3 emails with known scores: 40, 60, 80 → avg = 60.0
        await _insert_email(db, ws_id, threat_score=40.0)
        await _insert_email(db, ws_id, threat_score=60.0)
        await _insert_email(db, ws_id, threat_score=80.0)
        await db.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get(
            f"/api/v1/workspaces/{two_users['ws_a']}/stats",
            headers={"Authorization": f"Bearer {two_users['token_a']}"},
        )

    assert resp.status_code == 200
    data = resp.json()
    expected_avg = 60.0
    assert data["average_threat_score"] == pytest.approx(expected_avg, abs=0.01), (
        f"Expected avg threat score ~{expected_avg}, got {data['average_threat_score']}"
    )
    assert data["workspace_risk_score"] == data["average_threat_score"], (
        "workspace_risk_score must equal average_threat_score in Step 14"
    )


# ── Test 6: Weekly IOC filtering ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_weekly_ioc_filtering(two_users):
    """
    high_critical_iocs_this_week must only count IOCs with:
      - threat_score >= 70
      - created_at within the current calendar week (Monday 00:00 UTC to now)

    IOCs older than one week or with score < 70 must NOT be counted.
    """
    ws_id = uuid.UUID(two_users["ws_a"])

    from app.db.session import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        ea_id = await _insert_email(db, ws_id)

        # Should be counted: high score, this week
        await _insert_ioc(db, ws_id, ea_id, threat_score=85, days_ago=0)
        await _insert_ioc(db, ws_id, ea_id, threat_score=70, days_ago=0)

        # Should NOT be counted: score below threshold
        await _insert_ioc(db, ws_id, ea_id, threat_score=69, days_ago=0)
        await _insert_ioc(db, ws_id, ea_id, threat_score=0, days_ago=0)

        # Should NOT be counted: old (8 days ago = definitely last week or earlier)
        await _insert_ioc(db, ws_id, ea_id, threat_score=90, days_ago=8)

        await db.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get(
            f"/api/v1/workspaces/{two_users['ws_a']}/stats",
            headers={"Authorization": f"Bearer {two_users['token_a']}"},
        )

    assert resp.status_code == 200
    data = resp.json()
    # Exactly 2 IOCs should qualify (scores 85 and 70, this week)
    assert data["high_critical_iocs_this_week"] == 2, (
        f"Expected 2 high/critical IOCs this week, got {data['high_critical_iocs_this_week']}"
    )


# ── Test 7: Email BOLA regression — workspace isolation ───────────────────────

@pytest.mark.asyncio
async def test_email_list_workspace_isolation():
    """
    BOLA regression test for Step 14's email endpoint security fix.

    - User A creates Workspace A and uploads an email to it.
    - User B creates Workspace B.
    - User B must NOT receive User A's emails when querying their own workspace.
    - User A must NOT receive User B's emails when querying their own workspace.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        token_a = await _register_and_login(ac, "bola_a@test.com", "SuperSecret123!", "BOLA A")
        token_b = await _register_and_login(ac, "bola_b@test.com", "SuperSecret123!", "BOLA B")
        ws_a = await _create_workspace(ac, token_a, "BOLA Workspace A")
        ws_b = await _create_workspace(ac, token_b, "BOLA Workspace B")

    ws_a_id = uuid.UUID(ws_a)
    ws_b_id = uuid.UUID(ws_b)

    # Directly insert emails into each workspace
    from app.db.session import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        email_a_id = await _insert_email(db, ws_a_id, threat_score=75.0, severity="HIGH")
        email_b_id = await _insert_email(db, ws_b_id, threat_score=90.0, severity="CRITICAL")
        await db.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # User A queries their workspace — should see their email, NOT User B's
        resp_a = await ac.get(
            "/api/v1/emails/",
            params={"workspace_id": str(ws_a_id)},
            headers={"Authorization": f"Bearer {token_a}"},
        )
        assert resp_a.status_code == 200, resp_a.text
        ids_a = {item["id"] for item in resp_a.json()["items"]}
        assert str(email_a_id) in ids_a, "User A's email not returned in their workspace"
        assert str(email_b_id) not in ids_a, "User B's email leaked into User A's workspace!"

        # User B queries their workspace — should see their email, NOT User A's
        resp_b = await ac.get(
            "/api/v1/emails/",
            params={"workspace_id": str(ws_b_id)},
            headers={"Authorization": f"Bearer {token_b}"},
        )
        assert resp_b.status_code == 200, resp_b.text
        ids_b = {item["id"] for item in resp_b.json()["items"]}
        assert str(email_b_id) in ids_b, "User B's email not returned in their workspace"
        assert str(email_a_id) not in ids_b, "User A's email leaked into User B's workspace!"

        # User B CANNOT query User A's workspace (cross-workspace BOLA attempt)
        resp_cross = await ac.get(
            "/api/v1/emails/",
            params={"workspace_id": str(ws_a_id)},
            headers={"Authorization": f"Bearer {token_b}"},
        )
        assert resp_cross.status_code == 404, (
            f"Expected 404 for cross-workspace email access, got {resp_cross.status_code}"
        )
