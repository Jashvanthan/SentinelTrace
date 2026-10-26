import asyncio
import uuid
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select
from app.main import app
from app.db.session import AsyncSessionLocal
from app.models.user import User, UserRole
from app.models.refresh_session import RefreshSession
from app.services.password_service import hash_password
from app.api.v1.auth import _get_google_redirect_uri
from starlette.requests import Request


@pytest.mark.asyncio
async def test_incorrect_credentials_error_message():
    """Verify that wrong email or wrong password returns uniform 'Incorrect username or password'."""
    test_email = f"user_test_{uuid.uuid4().hex[:8]}@sentineltrace.io"
    password = "CorrectPassword123!"

    async with AsyncSessionLocal() as session:
        user = User(
            email=test_email,
            full_name="Analyst Test",
            password_hash=hash_password(password),
            role=UserRole.ANALYST,
            is_active=True,
        )
        session.add(user)
        await session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Case A: Non-existent email
        resp_not_found = await ac.post(
            "/api/v1/auth/login",
            json={"email": "nonexistent_analyst@domain.com", "password": "AnyPassword123!"},
        )
        assert resp_not_found.status_code == 401
        assert resp_not_found.json().get("detail") == "Incorrect username or password"

        # Case B: Existent email, wrong password
        resp_wrong_pass = await ac.post(
            "/api/v1/auth/login",
            json={"email": test_email, "password": "WrongPassword999!"},
        )
        assert resp_wrong_pass.status_code == 401
        assert resp_wrong_pass.json().get("detail") == "Incorrect username or password"


@pytest.mark.asyncio
async def test_multi_agent_concurrent_logins():
    """Verify system stability when multiple agents log in simultaneously at the same time."""
    num_agents = 4
    agents_data = []

    async with AsyncSessionLocal() as session:
        for i in range(num_agents):
            email = f"agent_{i}_{uuid.uuid4().hex[:6]}@sentineltrace.io"
            pw = f"AgentSecret_{i}_2026!"
            user = User(
                email=email,
                full_name=f"Agent {i}",
                password_hash=hash_password(pw),
                role=UserRole.ANALYST,
                is_active=True,
            )
            session.add(user)
            agents_data.append((email, pw))
        await session.commit()

    async def agent_login(email: str, password: str):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            return await ac.post(
                "/api/v1/auth/login",
                json={"email": email, "password": password},
            )

    # Launch all agent login requests concurrently in parallel
    tasks = [agent_login(email, pw) for email, pw in agents_data]
    responses = await asyncio.gather(*tasks)

    # All concurrent requests must succeed without crash or deadlock
    assert len(responses) == num_agents
    for resp in responses:
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "st_refresh_token" in resp.cookies


@pytest.mark.asyncio
async def test_multi_device_session_isolation_and_cookies():
    """
    Verify same user logging in on different devices (Desktop vs Mobile):
    - Independent refresh token cookies and family IDs
    - Device 1 rotation does not invalidate Device 2
    """
    email = f"multidevice_{uuid.uuid4().hex[:6]}@sentineltrace.io"
    password = "MultiDevicePass123!"

    async with AsyncSessionLocal() as session:
        user = User(
            email=email,
            full_name="SOC Lead Device",
            password_hash=hash_password(password),
            role=UserRole.ANALYST,
            is_active=True,
        )
        session.add(user)
        await session.commit()
        user_id = user.id

    desktop_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"}
    mobile_headers = {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148"}

    # Device 1: Desktop Login
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=desktop_headers) as desktop_client:
        d_resp = await desktop_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert d_resp.status_code == 200
        desktop_cookie = d_resp.cookies.get("st_refresh_token")
        assert desktop_cookie is not None

        # Device 2: Mobile Login (Same user, different device)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=mobile_headers) as mobile_client:
            m_resp = await mobile_client.post(
                "/api/v1/auth/login",
                json={"email": email, "password": password},
            )
            assert m_resp.status_code == 200
            mobile_cookie = m_resp.cookies.get("st_refresh_token")
            assert mobile_cookie is not None
            assert desktop_cookie != mobile_cookie

            # Verify in DB that both sessions have distinct family_ids
            async with AsyncSessionLocal() as session:
                sessions = (
                    await session.scalars(
                        select(RefreshSession).where(RefreshSession.user_id == user_id, RefreshSession.revoked.is_(False))
                    )
                ).all()
                assert len(sessions) == 2
                assert sessions[0].family_id != sessions[1].family_id

            # Device 1 (Desktop) refreshes its token
            d_refresh = await desktop_client.post("/api/v1/auth/refresh")
            assert d_refresh.status_code == 200
            new_desktop_cookie = d_refresh.cookies.get("st_refresh_token")
            assert new_desktop_cookie is not None
            assert new_desktop_cookie != desktop_cookie

            # Device 2 (Mobile) refreshes its token — must STILL be valid and unaffected
            m_refresh = await mobile_client.post("/api/v1/auth/refresh")
            assert m_refresh.status_code == 200
            new_mobile_cookie = m_refresh.cookies.get("st_refresh_token")
            assert new_mobile_cookie is not None
            assert new_mobile_cookie != mobile_cookie


@pytest.mark.asyncio
async def test_multi_device_logout_all():
    """Verify that logging out from all devices invalidates both desktop and mobile sessions."""
    email = f"logoutall_{uuid.uuid4().hex[:6]}@sentineltrace.io"
    password = "LogoutAllPass123!"

    async with AsyncSessionLocal() as session:
        user = User(
            email=email,
            full_name="Admin LogoutAll",
            password_hash=hash_password(password),
            role=UserRole.ADMIN,
            is_active=True,
        )
        session.add(user)
        await session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as d_client:
        d_login = await d_client.post("/api/v1/auth/login", json={"email": email, "password": password})
        d_token = d_login.json()["access_token"]

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as m_client:
            m_login = await m_client.post("/api/v1/auth/login", json={"email": email, "password": password})
            assert m_login.status_code == 200

            # User triggers Logout All Devices from Desktop
            lo_resp = await d_client.post(
                "/api/v1/auth/logout-all",
                headers={"Authorization": f"Bearer {d_token}"},
            )
            assert lo_resp.status_code in (200, 204)

            # Both devices' refresh tokens should now be rejected
            m_refresh_after = await m_client.post("/api/v1/auth/refresh")
            assert m_refresh_after.status_code == 401

            d_refresh_after = await d_client.post("/api/v1/auth/refresh")
            assert d_refresh_after.status_code == 401


def test_google_mobile_ip_redirect_uri_safety():
    """Verify that mobile requests coming from numeric LAN IPs fall back safely to configured redirect URI."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/auth/google",
        "headers": [
            (b"host", b"192.168.1.100:8000"),
            (b"user-agent", b"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148"),
        ],
    }
    request = Request(scope)
    redirect_uri = _get_google_redirect_uri(request)
    assert "192.168.1.100" not in redirect_uri
    assert "http" in redirect_uri


@pytest.mark.asyncio
async def test_multi_device_list_and_individual_revocation():
    """
    Verify:
    1. User can log in simultaneously from Desktop and Mobile.
    2. GET /auth/sessions returns both devices with accurate device types (desktop, mobile).
    3. User can revoke the mobile session from desktop.
    4. Mobile refresh is rejected while desktop session continues to work.
    """
    email = f"session_mgmt_{uuid.uuid4().hex[:6]}@sentineltrace.io"
    password = "SessionSecure2026!"

    async with AsyncSessionLocal() as session:
        user = User(
            email=email,
            full_name="SOC Analyst MultiDevice",
            password_hash=hash_password(password),
            role=UserRole.ANALYST,
            is_active=True,
        )
        session.add(user)
        await session.commit()

    desktop_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"}
    mobile_headers = {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148"}

    # Step 1: Desktop Login
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=desktop_headers) as d_client:
        d_login = await d_client.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert d_login.status_code == 200
        d_token = d_login.json()["access_token"]

        # Step 2: Mobile Login (same user)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=mobile_headers) as m_client:
            m_login = await m_client.post("/api/v1/auth/login", json={"email": email, "password": password})
            assert m_login.status_code == 200

            # Step 3: Desktop queries GET /auth/sessions
            sessions_resp = await d_client.get(
                "/api/v1/auth/sessions",
                headers={"Authorization": f"Bearer {d_token}"},
            )
            assert sessions_resp.status_code == 200
            session_data = sessions_resp.json()
            assert session_data["total_active"] == 2
            sessions_list = session_data["sessions"]

            # Verify device types and current device flag
            device_types = [s["device_type"] for s in sessions_list]
            assert "mobile" in device_types
            assert "desktop" in device_types

            current_sessions = [s for s in sessions_list if s["is_current"]]
            assert len(current_sessions) == 1
            assert current_sessions[0]["device_type"] == "desktop"

            # Find mobile family_id
            mobile_session = next(s for s in sessions_list if s["device_type"] == "mobile")
            mobile_family_id = mobile_session["family_id"]

            # Step 4: Desktop revokes Mobile session
            revoke_resp = await d_client.delete(
                f"/api/v1/auth/sessions/{mobile_family_id}",
                headers={"Authorization": f"Bearer {d_token}"},
            )
            assert revoke_resp.status_code == 200
            assert revoke_resp.json()["status"] == "REVOKED"

            # Step 5: Mobile device tries to refresh -> MUST be rejected (401)
            m_refresh = await m_client.post("/api/v1/auth/refresh")
            assert m_refresh.status_code == 401

            # Desktop device tries to refresh -> MUST succeed
            d_refresh = await d_client.post("/api/v1/auth/refresh")
            assert d_refresh.status_code == 200


@pytest.mark.asyncio
async def test_multi_device_revoke_others():
    """
    Verify POST /auth/sessions/revoke-others terminates all other device sessions
    while keeping the active caller's device session intact.
    """
    email = f"revoke_others_{uuid.uuid4().hex[:6]}@sentineltrace.io"
    password = "RevokeOthers2026!"

    async with AsyncSessionLocal() as session:
        user = User(
            email=email,
            full_name="SOC Analyst RevokeOthers",
            password_hash=hash_password(password),
            role=UserRole.ANALYST,
            is_active=True,
        )
        session.add(user)
        await session.commit()

    d_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"}
    m_headers = {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile/15E148"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=d_headers) as d_client:
        d_login = await d_client.post("/api/v1/auth/login", json={"email": email, "password": password})
        d_token = d_login.json()["access_token"]

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=m_headers) as m_client:
            await m_client.post("/api/v1/auth/login", json={"email": email, "password": password})

            # Desktop calls revoke-others
            rev_resp = await d_client.post(
                "/api/v1/auth/sessions/revoke-others",
                headers={"Authorization": f"Bearer {d_token}"},
            )
            assert rev_resp.status_code == 200
            assert rev_resp.json()["status"] == "SUCCESS"
            assert rev_resp.json()["revoked_count"] >= 1

            # Mobile refresh is now rejected
            m_refresh = await m_client.post("/api/v1/auth/refresh")
            assert m_refresh.status_code == 401

            # Desktop refresh still works
            d_refresh = await d_client.post("/api/v1/auth/refresh")
            assert d_refresh.status_code == 200

