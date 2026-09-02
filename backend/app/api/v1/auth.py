"""
SentinelTrace Backend — Auth API Router

Endpoints:
  POST /auth/register        Register a new local user
  POST /auth/login           Email/password login → access token + refresh cookie
  POST /auth/refresh         Refresh access token using HttpOnly cookie
  POST /auth/logout          Revoke refresh token
  GET  /auth/me              Get current user info
  GET  /auth/google          Get Google OAuth authorization URL
  GET  /auth/google/callback Handle Google OAuth callback
"""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from app.core.config import get_settings
from app.core.deps import CurrentUser, DbSession
from app.core.security import REFRESH_TOKEN_COOKIE_NAME
from app.schemas.auth import (
    GoogleOAuthURLResponse,
    LoginRequest,
    TokenResponse,
    UserRegisterRequest,
    UserResponse,
)
from app.services.auth_service import (
    authenticate_user,
    logout_user,
    logout_all_user,
    register_user,
    rotate_refresh_token,
    upsert_google_user,
    create_oauth_state,
    validate_and_consume_oauth_state,
)

# For rate limiting
from fastapi import Depends
from fastapi_limiter.depends import RateLimiter

router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def register(
    payload: UserRegisterRequest,
    db: DbSession,
    request: Request,
):
    """Register a new local user account."""
    user = await register_user(db, payload, request)
    return user


@router.post("/login", response_model=TokenResponse, dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def login(
    payload: LoginRequest,
    db: DbSession,
    request: Request,
    response: Response,
):
    """
    Authenticate with email and password.

    Returns:
    - JSON: `{ access_token, token_type, expires_in, user }`
    - Cookie: `st_refresh_token` (HttpOnly, Secure, SameSite=Strict)
    """
    return await authenticate_user(db, payload, request, response)


@router.post("/refresh", response_model=TokenResponse, dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def refresh(
    db: DbSession,
    request: Request,
    response: Response,
    refresh_token_cookie: str | None = Cookie(None, alias=REFRESH_TOKEN_COOKIE_NAME),
):
    """
    Rotate refresh token and issue a new access token.
    The refresh token is read from the HttpOnly cookie.
    """
    raw_token = refresh_token_cookie
    if not raw_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token missing")
    return await rotate_refresh_token(db, raw_token, request, response)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    db: DbSession,
    response: Response,
    current_user: CurrentUser,
    refresh_token_cookie: str | None = Cookie(None, alias=REFRESH_TOKEN_COOKIE_NAME),
):
    """Revoke the current refresh token and clear the cookie."""
    await logout_user(db, refresh_token_cookie, current_user.id, response)


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(
    db: DbSession,
    response: Response,
    current_user: CurrentUser,
):
    """Revoke all refresh sessions for the user and clear the cookie."""
    await logout_all_user(db, current_user.id, response)


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: CurrentUser):
    """Return the currently authenticated user's profile."""
    return current_user


# ── Google OAuth ──────────────────────────────────────────────────────────────

@router.get("/google", response_model=GoogleOAuthURLResponse)
async def google_oauth_start(
    db: DbSession,
    response: Response,
):
    """
    Generate the Google OAuth 2.0 authorization URL and secure state.
    Binds the state to a browser_nonce stored in an HttpOnly, Lax cookie.
    """
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        raise HTTPException(
            status.HTTP_501_NOT_IMPLEMENTED,
            "Google OAuth is not configured on this server",
        )

    from authlib.integrations.httpx_client import AsyncOAuth2Client

    state_nonce = secrets.token_urlsafe(32)
    browser_nonce = secrets.token_urlsafe(32)
    
    # Store state in DB
    await create_oauth_state(db, state_nonce, browser_nonce)

    client = AsyncOAuth2Client(
        client_id=settings.GOOGLE_CLIENT_ID,
        redirect_uri=settings.GOOGLE_REDIRECT_URI,
        scope="openid email profile",  # ONLY identity scopes allowed
    )
    auth_url, _ = client.create_authorization_url(
        "https://accounts.google.com/o/oauth2/v2/auth",
        state=state_nonce,
        access_type="offline",
        prompt="consent",
    )
    
    response.set_cookie(
        key="st_oauth_nonce",
        value=browser_nonce,
        httponly=True,
        secure=settings.APP_ENV == "production",
        samesite="lax",
        max_age=600,  # 10 minutes
    )
    
    return GoogleOAuthURLResponse(authorization_url=auth_url, state=state_nonce)


@router.get("/google/callback")
async def google_oauth_callback(
    code: str,
    state: str,
    db: DbSession,
    request: Request,
    response: Response,
):
    """
    Handle Google OAuth 2.0 callback.
    Exchanges the authorization code server-side and issues SentinelTrace JWT.
    Redirects back to frontend dashboard safely.
    """
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, "Google OAuth not configured")

    # 1. Validate State Binding
    browser_nonce = request.cookies.get("st_oauth_nonce")
    if not browser_nonce:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "OAuth state cookie missing. Flow rejected.")
    
    # 2. Consume State from DB
    await validate_and_consume_oauth_state(db, state, browser_nonce)

    # Clear nonce cookie
    response.delete_cookie("st_oauth_nonce", samesite="lax")

    try:
        from authlib.integrations.httpx_client import AsyncOAuth2Client
        from google.oauth2 import id_token as google_id_token
        from google.auth.transport import requests as google_requests

        # 3. Exchange Code
        client = AsyncOAuth2Client(
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
            redirect_uri=settings.GOOGLE_REDIRECT_URI,
        )
        token_data = await client.fetch_token(
            "https://oauth2.googleapis.com/token",
            code=code,
        )

        # 4. Verify ID Token mathematically using Google's JWKS
        raw_id_token = token_data.get("id_token")
        if not raw_id_token:
            raise ValueError("Missing id_token from Google")

        request_adapter = google_requests.Request()
        id_info = google_id_token.verify_oauth2_token(
            raw_id_token, 
            request_adapter, 
            settings.GOOGLE_CLIENT_ID
        )

        if id_info["iss"] not in ["accounts.google.com", "https://accounts.google.com"]:
            raise ValueError("Wrong issuer.")

        # 5. Create / Login User
        # Raw OAuth tokens are discarded immediately
        await upsert_google_user(db, id_info, request, response)

        # 6. Secure Redirect to Frontend
        frontend_url = settings.FRONTEND_URL or "http://localhost:5173"
        return RedirectResponse(
            url=f"{frontend_url}/?google_auth=success",
            status_code=status.HTTP_302_FOUND,
            headers=response.headers, # preserve cookies (st_refresh_token)
        )
    except HTTPException as e:
        frontend_url = settings.FRONTEND_URL or "http://localhost:5173"
        error_code = "google_auth_failed"
        if e.status_code == 409:
            error_code = "account_exists"
        return RedirectResponse(
            url=f"{frontend_url}/login?error={error_code}",
            status_code=status.HTTP_302_FOUND
        )
    except Exception as e:
        frontend_url = settings.FRONTEND_URL or "http://localhost:5173"
        return RedirectResponse(
            url=f"{frontend_url}/login?error=google_auth_failed",
            status_code=status.HTTP_302_FOUND
        )


