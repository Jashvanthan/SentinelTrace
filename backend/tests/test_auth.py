import asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app

async def test_registration_success():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/v1/auth/register", json={
            "email": "newuser@test.com",
            "password": "SuperSecretPassword123",
            "full_name": "New User"
        })
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "newuser@test.com"
    print("  ✓ Authentication Registration test passed")

async def test_registration_duplicate_prevention_enumeration():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # First register
        await ac.post("/api/v1/auth/register", json={
            "email": "enum@test.com",
            "password": "SuperSecretPassword123",
            "full_name": "Enum User"
        })
        # Try again
        response = await ac.post("/api/v1/auth/register", json={
            "email": "enum@test.com",
            "password": "AnotherPassword456",
            "full_name": "Enum User"
        })
    assert response.status_code == 201
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        login_resp = await ac.post("/api/v1/auth/login", json={
            "email": "enum@test.com",
            "password": "AnotherPassword456"
        })
        assert login_resp.status_code == 401
    print("  ✓ Registration Duplicate Prevention / Enumeration test passed")

async def test_login_success():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await ac.post("/api/v1/auth/register", json={
            "email": "loginuser@test.com",
            "password": "SuperSecretPassword123",
            "full_name": "Login User"
        })
        response = await ac.post("/api/v1/auth/login", json={
            "email": "loginuser@test.com",
            "password": "SuperSecretPassword123"
        })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "st_refresh_token" in response.cookies
    print("  ✓ Login Success test passed")

async def test_login_wrong_password():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/v1/auth/login", json={
            "email": "loginuser@test.com",
            "password": "WrongPassword123"
        })
    assert response.status_code == 401
    print("  ✓ Login Wrong Password rejection passed")

async def test_refresh_rotation_and_reuse_detection():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await ac.post("/api/v1/auth/register", json={
            "email": "refreshuser@test.com",
            "password": "SuperSecretPassword123",
            "full_name": "Refresh User"
        })
        login_resp = await ac.post("/api/v1/auth/login", json={
            "email": "refreshuser@test.com",
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
    print("  ✓ Token Rotation & Reuse Detection passed")

async def test_logout():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await ac.post("/api/v1/auth/register", json={
            "email": "logout@test.com",
            "password": "SuperSecretPassword123",
            "full_name": "Logout"
        })
        login_resp = await ac.post("/api/v1/auth/login", json={
            "email": "logout@test.com",
            "password": "SuperSecretPassword123"
        })
        token = login_resp.json()["access_token"]
        
        logout_resp = await ac.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert logout_resp.status_code == 204
        
        refresh_resp = await ac.post("/api/v1/auth/refresh")
        assert refresh_resp.status_code == 401
    print("  ✓ Logout test passed")

async def run_all():
    print("\n--- Testing Authentication API ---")
    await test_registration_success()
    await test_registration_duplicate_prevention_enumeration()
    await test_login_success()
    await test_login_wrong_password()
    await test_refresh_rotation_and_reuse_detection()
    await test_logout()
    print("ALL AUTH TESTS PASSED!")

def main():
    asyncio.run(run_all())

if __name__ == "__main__":
    main()



