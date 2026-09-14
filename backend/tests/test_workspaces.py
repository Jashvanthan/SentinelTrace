import asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app

async def get_users():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await ac.post("/api/v1/auth/register", json={
            "email": "usera@test.com", "password": "SuperSecretPassword123", "full_name": "User A"
        })
        resp_a = await ac.post("/api/v1/auth/login", json={
            "email": "usera@test.com", "password": "SuperSecretPassword123"
        })
        token_a = resp_a.json()["access_token"]

        await ac.post("/api/v1/auth/register", json={
            "email": "userb@test.com", "password": "SuperSecretPassword123", "full_name": "User B"
        })
        resp_b = await ac.post("/api/v1/auth/login", json={
            "email": "userb@test.com", "password": "SuperSecretPassword123"
        })
        token_b = resp_b.json()["access_token"]

        return {"user_a": token_a, "user_b": token_b}

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
    print("  ✓ Workspace Creation test passed")

async def test_idor_cross_workspace_access(users):
    token_a = users["user_a"]
    token_b = users["user_b"]
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post(
            "/api/v1/workspaces",
            json={"name": "User A Workspace"},
            headers={"Authorization": f"Bearer {token_a}"}
        )
        ws_id = resp.json()["id"]

        resp_b = await ac.get(
            f"/api/v1/workspaces/{ws_id}/members",
            headers={"Authorization": f"Bearer {token_b}"}
        )
        assert resp_b.status_code == 404
    print("  ✓ IDOR Cross-Workspace Access Prevention passed")

async def test_rbac_member_management(users):
    token_a = users["user_a"]
    token_b = users["user_b"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post(
            "/api/v1/workspaces",
            json={"name": "Workspace A"},
            headers={"Authorization": f"Bearer {token_a}"}
        )
        ws_id = resp.json()["id"]

        add_resp = await ac.post(
            f"/api/v1/workspaces/{ws_id}/members",
            json={"email": "userb@test.com", "role": "viewer"},
            headers={"Authorization": f"Bearer {token_a}"}
        )
        assert add_resp.status_code == 200

        add_fail_resp = await ac.post(
            f"/api/v1/workspaces/{ws_id}/members",
            json={"email": "usera@test.com", "role": "viewer"},
            headers={"Authorization": f"Bearer {token_b}"}
        )
        assert add_fail_resp.status_code == 403
    print("  ✓ RBAC Member Management passed")

async def test_critical_idor_workspace_switching(users):
    token_a = users["user_a"]
    token_b = users["user_b"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp_a = await ac.post(
            "/api/v1/workspaces",
            json={"name": "Workspace A"},
            headers={"Authorization": f"Bearer {token_a}"}
        )
        ws_a_id = resp_a.json()["id"]

        resp_b = await ac.post(
            "/api/v1/workspaces",
            json={"name": "Workspace B"},
            headers={"Authorization": f"Bearer {token_b}"}
        )
        ws_b_id = resp_b.json()["id"]

        get_ws_a_by_a = await ac.get(
            f"/api/v1/workspaces/{ws_a_id}/members",
            headers={"Authorization": f"Bearer {token_a}"}
        )
        assert get_ws_a_by_a.status_code == 200

        get_ws_b_by_a = await ac.get(
            f"/api/v1/workspaces/{ws_b_id}/members",
            headers={"Authorization": f"Bearer {token_a}"}
        )
        assert get_ws_b_by_a.status_code == 404

        get_ws_a_by_b = await ac.get(
            f"/api/v1/workspaces/{ws_a_id}/members",
            headers={"Authorization": f"Bearer {token_b}"}
        )
        assert get_ws_a_by_b.status_code == 404

        await ac.post(
            f"/api/v1/workspaces/{ws_a_id}/members",
            json={"email": "userb@test.com", "role": "viewer"},
            headers={"Authorization": f"Bearer {token_a}"}
        )
        
        get_ws_a_by_b_after = await ac.get(
            f"/api/v1/workspaces/{ws_a_id}/members",
            headers={"Authorization": f"Bearer {token_b}"}
        )
        assert get_ws_a_by_b_after.status_code == 200
        user_b_member_id = [m["user_id"] for m in get_ws_a_by_b_after.json() if m["email"] == "userb@test.com"][0]

        remove_resp = await ac.delete(
            f"/api/v1/workspaces/{ws_a_id}/members/{user_b_member_id}",
            headers={"Authorization": f"Bearer {token_a}"}
        )
        assert remove_resp.status_code == 204

        get_ws_a_by_b_removed = await ac.get(
            f"/api/v1/workspaces/{ws_a_id}/members",
            headers={"Authorization": f"Bearer {token_b}"}
        )
        assert get_ws_a_by_b_removed.status_code == 404
    print("  ✓ Critical IDOR Workspace Switching test passed")

async def run_all():
    print("\n--- Testing Workspaces API ---")
    users = await get_users()
    await test_workspace_creation(users)
    await test_idor_cross_workspace_access(users)
    await test_rbac_member_management(users)
    await test_critical_idor_workspace_switching(users)
    print("ALL WORKSPACE TESTS PASSED!")

def main():
    asyncio.run(run_all())

if __name__ == "__main__":
    main()



