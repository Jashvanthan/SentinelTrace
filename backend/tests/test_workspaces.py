import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app

@pytest.fixture
async def users():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Create User A
        await ac.post("/api/v1/auth/register", json={
            "email": "usera@test.com", "password": "SuperSecretPassword123", "full_name": "User A"
        })
        resp_a = await ac.post("/api/v1/auth/login", json={
            "email": "usera@test.com", "password": "SuperSecretPassword123"
        })
        token_a = resp_a.json()["access_token"]

        # Create User B
        await ac.post("/api/v1/auth/register", json={
            "email": "userb@test.com", "password": "SuperSecretPassword123", "full_name": "User B"
        })
        resp_b = await ac.post("/api/v1/auth/login", json={
            "email": "userb@test.com", "password": "SuperSecretPassword123"
        })
        token_b = resp_b.json()["access_token"]

        return {"user_a": token_a, "user_b": token_b}


@pytest.mark.asyncio
async def test_workspace_creation(users):
    token = users["user_a"]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post(
            "/api/v1/workspaces",
            json={"name": "Workspace A"},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Workspace A"
        assert data["role"] == "owner"


@pytest.mark.asyncio
async def test_idor_cross_workspace_access(users):
    token_a = users["user_a"]
    token_b = users["user_b"]
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # User A creates workspace A
        resp = await ac.post(
            "/api/v1/workspaces",
            json={"name": "User A Workspace"},
            headers={"Authorization": f"Bearer {token_a}"}
        )
        ws_id = resp.json()["id"]

        # User B attempts to access Workspace A members
        resp_b = await ac.get(
            f"/api/v1/workspaces/{ws_id}/members",
            headers={"Authorization": f"Bearer {token_b}"}
        )
        assert resp_b.status_code == 404 # Not found / Enumeration prevention


@pytest.mark.asyncio
async def test_rbac_member_management(users):
    token_a = users["user_a"]
    token_b = users["user_b"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # User A creates workspace A
        resp = await ac.post(
            "/api/v1/workspaces",
            json={"name": "Workspace A"},
            headers={"Authorization": f"Bearer {token_a}"}
        )
        ws_id = resp.json()["id"]

        # User A (owner) adds User B as viewer
        add_resp = await ac.post(
            f"/api/v1/workspaces/{ws_id}/members",
            json={"email": "userb@test.com", "role": "viewer"},
            headers={"Authorization": f"Bearer {token_a}"}
        )
        assert add_resp.status_code == 200

        # User B (viewer) attempts to add a new member
        add_fail_resp = await ac.post(
            f"/api/v1/workspaces/{ws_id}/members",
            json={"email": "usera@test.com", "role": "viewer"},
            headers={"Authorization": f"Bearer {token_b}"}
        )
        assert add_fail_resp.status_code == 403 # Insufficient permissions


@pytest.mark.asyncio
async def test_critical_idor_workspace_switching(users):
    """
    Critical test:
    1. Login as User A.
    2. User A selects Workspace A.
    3. User A accesses Workspace A -> PASS.
    4. User A changes requested workspace ID to Workspace B.
    5. Backend rejects request.
    6. User B cannot access Workspace A.
    """
    token_a = users["user_a"]
    token_b = users["user_b"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Create Workspace A (User A is owner)
        resp_a = await ac.post(
            "/api/v1/workspaces",
            json={"name": "Workspace A"},
            headers={"Authorization": f"Bearer {token_a}"}
        )
        ws_a_id = resp_a.json()["id"]

        # Create Workspace B (User B is owner)
        resp_b = await ac.post(
            "/api/v1/workspaces",
            json={"name": "Workspace B"},
            headers={"Authorization": f"Bearer {token_b}"}
        )
        ws_b_id = resp_b.json()["id"]

        # 3. User A accesses Workspace A -> PASS
        get_ws_a_by_a = await ac.get(
            f"/api/v1/workspaces/{ws_a_id}/members",
            headers={"Authorization": f"Bearer {token_a}"}
        )
        assert get_ws_a_by_a.status_code == 200

        # 4 & 5. User A tries to access Workspace B -> DENIED (404 to prevent enumeration)
        get_ws_b_by_a = await ac.get(
            f"/api/v1/workspaces/{ws_b_id}/members",
            headers={"Authorization": f"Bearer {token_a}"}
        )
        assert get_ws_b_by_a.status_code == 404

        # 6. User B cannot access Workspace A -> DENIED
        get_ws_a_by_b = await ac.get(
            f"/api/v1/workspaces/{ws_a_id}/members",
            headers={"Authorization": f"Bearer {token_b}"}
        )
        assert get_ws_a_by_b.status_code == 404

        # 7. Test removing member immediately prevents access
        # Add User B to Workspace A
        await ac.post(
            f"/api/v1/workspaces/{ws_a_id}/members",
            json={"email": "userb@test.com", "role": "viewer"},
            headers={"Authorization": f"Bearer {token_a}"}
        )
        
        # User B can now access
        get_ws_a_by_b_after = await ac.get(
            f"/api/v1/workspaces/{ws_a_id}/members",
            headers={"Authorization": f"Bearer {token_b}"}
        )
        assert get_ws_a_by_b_after.status_code == 200
        user_b_member_id = [m["user_id"] for m in get_ws_a_by_b_after.json() if m["email"] == "userb@test.com"][0]

        # Remove User B
        remove_resp = await ac.delete(
            f"/api/v1/workspaces/{ws_a_id}/members/{user_b_member_id}",
            headers={"Authorization": f"Bearer {token_a}"}
        )
        assert remove_resp.status_code == 204

        # User B can NO LONGER access Workspace A
        get_ws_a_by_b_removed = await ac.get(
            f"/api/v1/workspaces/{ws_a_id}/members",
            headers={"Authorization": f"Bearer {token_b}"}
        )
        assert get_ws_a_by_b_removed.status_code == 404
