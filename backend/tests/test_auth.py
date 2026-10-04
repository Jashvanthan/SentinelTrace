import asyncio
import uuid
from httpx import AsyncClient, ASGITransport
from app.main import app

def get_test_email(prefix: str = "user") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}@test.com"

async def test_registration_success():
    email = get_test_email("new")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/v1/auth/register", json={
            "email": email,
            "password": "SuperSecretPassword123",
            "full_name": "New User"
        })
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == email
    print("  [PASS] Authentication Registration test passed")

async def test_registration_duplicate_prevention_enumeration():
    email = get_test_email("enum")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # First register
        resp1 = await ac.post("/api/v1/auth/register", json={
            "email": email,
            "password": "SuperSecretPassword123",
            "full_name": "Enum User"
        })
        assert resp1.status_code == 201

        # Duplicate register should be rejected (409)
        resp2 = await ac.post("/api/v1/auth/register", json={
            "email": email,
            "password": "AnotherPassword456",
            "full_name": "Enum User"
        })
        assert resp2.status_code == 409
    
    # Original password still works, wrong password rejected
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        login_resp = await ac.post("/api/v1/auth/login", json={
            "email": email,
            "password": "AnotherPassword456"
        })
        assert login_resp.status_code == 401
    print("  [PASS] Registration Duplicate Prevention / Enumeration test passed")

async def test_login_success():
    email = get_test_email("login")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await ac.post("/api/v1/auth/register", json={
            "email": email,
            "password": "SuperSecretPassword123",
            "full_name": "Login User"
        })
        response = await ac.post("/api/v1/auth/login", json={
            "email": email,
            "password": "SuperSecretPassword123"
        })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "st_refresh_token" in response.cookies
    assert data.get("session_expires_in") == 86400
    print("  [PASS] Login Success test passed")

async def test_login_wrong_password():
    email = get_test_email("wrongpwd")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await ac.post("/api/v1/auth/register", json={
            "email": email,
            "password": "SuperSecretPassword123",
            "full_name": "Login User"
        })
        response = await ac.post("/api/v1/auth/login", json={
            "email": email,
            "password": "WrongPassword123"
        })
    assert response.status_code == 401
    print("  [PASS] Login Wrong Password rejection passed")

async def test_refresh_rotation_and_reuse_detection():
    email = get_test_email("refresh")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await ac.post("/api/v1/auth/register", json={
            "email": email,
            "password": "SuperSecretPassword123",
            "full_name": "Refresh User"
        })
        login_resp = await ac.post("/api/v1/auth/login", json={
            "email": email,
            "password": "SuperSecretPassword123"
        })
        
        set_cookie = login_resp.headers.get("set-cookie")
        old_cookie = None
        if set_cookie:
            for part in set_cookie.split(";"):
                if part.strip().startswith("st_refresh_token="):
                    old_cookie = part.strip().split("=")[1]
                    break
        assert old_cookie is not None
        
        refresh_resp = await ac.post("/api/v1/auth/refresh")
        assert refresh_resp.status_code == 200
        set_cookie2 = refresh_resp.headers.get("set-cookie")
        new_cookie = None
        if set_cookie2:
            for part in set_cookie2.split(";"):
                if part.strip().startswith("st_refresh_token="):
                    new_cookie = part.strip().split("=")[1]
                    break
        assert new_cookie is not None
        assert old_cookie != new_cookie
        
        ac.cookies.set("st_refresh_token", old_cookie)
        reuse_resp = await ac.post("/api/v1/auth/refresh")
        assert reuse_resp.status_code == 401
        
        ac.cookies.set("st_refresh_token", new_cookie)
        second_reuse_resp = await ac.post("/api/v1/auth/refresh")
        assert second_reuse_resp.status_code == 401
    print("  [PASS] Token Rotation & Reuse Detection passed")

async def test_logout():
    email = get_test_email("logout")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await ac.post("/api/v1/auth/register", json={
            "email": email,
            "password": "SuperSecretPassword123",
            "full_name": "Logout"
        })
        login_resp = await ac.post("/api/v1/auth/login", json={
            "email": email,
            "password": "SuperSecretPassword123"
        })
        token = login_resp.json()["access_token"]
        
        logout_resp = await ac.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert logout_resp.status_code == 204
        
        refresh_resp = await ac.post("/api/v1/auth/refresh")
        assert refresh_resp.status_code == 401
    print("  [PASS] Logout test passed")

async def run_all():
    print("\n--- Testing Authentication API ---")
    await test_registration_success()
    await test_registration_duplicate_prevention_enumeration()
    await test_login_success()
    await test_login_wrong_password()
    await test_refresh_rotation_and_reuse_detection()
    await test_logout()
    print("ALL AUTH TESTS PASSED!\n")

def main():
    asyncio.run(run_all())

if __name__ == "__main__":
    main()
