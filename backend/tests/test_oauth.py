import pytest
from httpx import AsyncClient, ASGITransport
from urllib.parse import urlparse, parse_qs
from app.main import app
from app.models.oauth import OAuthState, ExternalIdentity
from app.models.user import User, AuthProvider
from sqlalchemy import select
from datetime import datetime, UTC
from unittest.mock import patch, MagicMock
import pytest_asyncio
from app.db.session import AsyncSessionLocal
from app.core.config import get_settings

settings = get_settings()

@pytest.fixture(autouse=True)
def mock_google_settings():
    settings.GOOGLE_CLIENT_ID = "mock_client_id"
    settings.GOOGLE_CLIENT_SECRET = "mock_client_secret"
    settings.GOOGLE_REDIRECT_URI = "http://test/api/v1/auth/google/callback"
    settings.FRONTEND_URL = "http://test-frontend"
    yield
    settings.GOOGLE_CLIENT_ID = None
    settings.GOOGLE_CLIENT_SECRET = None
    settings.GOOGLE_REDIRECT_URI = None
    settings.FRONTEND_URL = None

@pytest_asyncio.fixture
async def db_session():
    async with AsyncSessionLocal() as session:
        yield session

@pytest.mark.asyncio
async def test_oauth_start_generates_state_and_cookie(db_session):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/api/v1/auth/google")
    assert response.status_code == 200
    data = response.json()
    assert "authorization_url" in data
    assert "state" in data
    
    # Check NO Gmail scopes
    parsed_url = urlparse(data["authorization_url"])
    query_params = parse_qs(parsed_url.query)
    assert "scope" in query_params
    scopes = query_params["scope"][0]
    assert "openid email profile" == scopes
    assert "mail.google.com" not in scopes

    # Check cookie
    assert "st_oauth_nonce" in response.cookies
    browser_nonce = response.cookies["st_oauth_nonce"]

    # Check DB state
    state_val = data["state"]
    db_state = await db_session.get(OAuthState, state_val)
    assert db_state is not None
    assert db_state.browser_nonce == browser_nonce

@pytest.mark.asyncio
async def test_oauth_callback_browser_mismatch(db_session):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        start_resp = await ac.get("/api/v1/auth/google")
        state = start_resp.json()["state"]

        # Drop the cookie (simulate mismatch or missing)
        ac.cookies.delete("st_oauth_nonce")
        cb_resp = await ac.get(
            "/api/v1/auth/google/callback",
            params={"code": "dummycode", "state": state},
            follow_redirects=False
        )
        assert cb_resp.status_code == 400
        assert "cookie missing" in cb_resp.text.lower()
        
        # Add a wrong cookie
        ac.cookies.set("st_oauth_nonce", "wrongnonce")
        cb_resp2 = await ac.get(
            "/api/v1/auth/google/callback",
            params={"code": "dummycode", "state": state},
            follow_redirects=False
        )
        assert cb_resp2.status_code == 400
        assert "mismatch" in cb_resp2.text.lower()

@pytest.mark.asyncio
async def test_oauth_callback_state_single_use(db_session):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        start_resp = await ac.get("/api/v1/auth/google")
        state = start_resp.json()["state"]
        browser_nonce = start_resp.cookies["st_oauth_nonce"]

        # Call callback - should fail at token exchange because dummycode is invalid,
        # Simulate an error during token exchange to consume the state without completing login
        with patch("authlib.integrations.httpx_client.AsyncOAuth2Client.fetch_token") as mock_fetch:
            async def mock_fetch_error(*args, **kwargs):
                raise ValueError("Invalid code")
            mock_fetch.side_effect = mock_fetch_error
            
            cb_resp1 = await ac.get(
                "/api/v1/auth/google/callback",
                params={"code": "dummy_code", "state": state},
                cookies={"st_oauth_nonce": browser_nonce},
                follow_redirects=False
            )
            assert cb_resp1.status_code == 302
            assert "error=google_auth_failed" in cb_resp1.headers["location"]
        
        # State must be deleted
        db_state = await db_session.get(OAuthState, state)
        assert db_state is None

@pytest.mark.asyncio
async def test_upsert_google_user_collision(db_session):
    # 1. Register a LOCAL user
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await ac.post("/api/v1/auth/register", json={
            "email": "collision@test.com",
            "password": "Password123!",
            "full_name": "Local User"
        })
        
        start_resp = await ac.get("/api/v1/auth/google")
        state = start_resp.json()["state"]
        browser_nonce = start_resp.cookies["st_oauth_nonce"]
        
        # Mock Google token exchange and verification
        with patch("authlib.integrations.httpx_client.AsyncOAuth2Client.fetch_token") as mock_fetch:
            async def mock_fetch_coro(*args, **kwargs):
                return {"id_token": "dummy_raw_id_token", "access_token": "dummy"}
            mock_fetch.side_effect = mock_fetch_coro
            
            with patch("google.oauth2.id_token.verify_oauth2_token") as mock_verify:
                mock_verify.return_value = {
                    "iss": "accounts.google.com",
                    "aud": "myclientid",
                    "sub": "google123",
                    "email": "collision@test.com",
                    "email_verified": True,
                    "name": "Collision User",
                }
                
                # Make callback
                cb_resp = await ac.get(
                    "/api/v1/auth/google/callback",
                    params={"code": "realcode", "state": state},
                    cookies={"st_oauth_nonce": browser_nonce},
                    follow_redirects=False
                )
                assert cb_resp.status_code == 302
                assert "error=account_exists" in cb_resp.headers["location"]
                
                # Let's see if the user auth_provider changed
                user = await db_session.scalar(select(User).where(User.email == "collision@test.com"))
                assert user.auth_provider == AuthProvider.LOCAL
                
                # Check that no external identity was linked
                ext_id = await db_session.scalar(select(ExternalIdentity).where(ExternalIdentity.email == "collision@test.com"))
                assert ext_id is None

@pytest.mark.asyncio
async def test_upsert_google_user_new(db_session):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        start_resp = await ac.get("/api/v1/auth/google")
        state = start_resp.json()["state"]
        browser_nonce = start_resp.cookies["st_oauth_nonce"]
        
        with patch("authlib.integrations.httpx_client.AsyncOAuth2Client.fetch_token") as mock_fetch:
            async def mock_fetch_coro(*args, **kwargs):
                return {"id_token": "dummy_raw_id_token", "access_token": "dummy"}
            mock_fetch.side_effect = mock_fetch_coro
            
            with patch("google.oauth2.id_token.verify_oauth2_token") as mock_verify:
                mock_verify.return_value = {
                    "iss": "accounts.google.com",
                    "aud": "myclientid",
                    "sub": "googlenew123",
                    "email": "newgoogle@test.com",
                    "email_verified": True,
                    "name": "New Google User",
                }
                
                cb_resp = await ac.get(
                    "/api/v1/auth/google/callback",
                    params={"code": "realcode", "state": state},
                    cookies={"st_oauth_nonce": browser_nonce},
                    follow_redirects=False
                )
                assert cb_resp.status_code == 302
                assert "google_auth=success" in cb_resp.headers["location"]
                
                # Should have refresh token cookie
                assert "st_refresh_token" in cb_resp.cookies
                
                user = await db_session.scalar(select(User).where(User.email == "newgoogle@test.com"))
                assert user is not None
                assert user.auth_provider == AuthProvider.GOOGLE
                
                ext_id = await db_session.scalar(select(ExternalIdentity).where(ExternalIdentity.user_id == user.id))
                assert ext_id is not None
                assert ext_id.provider == "google"
                assert ext_id.provider_subject == "googlenew123"
