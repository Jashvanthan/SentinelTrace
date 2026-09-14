"""
SentinelTrace Backend — Auth API Router

Endpoints:
  POST /auth/register                    Register a new local user
  POST /auth/login                       Email/password login
  POST /auth/refresh                     Rotate access token via refresh cookie
  POST /auth/logout                      Revoke refresh token
  GET  /auth/me                          Get current user info
  GET  /auth/google?intent=login|register   Get Google OAuth URL (with intent)
  GET  /auth/google/callback             Handle Google OAuth callback
  POST /auth/google/complete-registration  Finalize Google registration (pending token)

Google OAuth security model:
  - intent=login  → Only logs in EXISTING SentinelTrace accounts
  - intent=register → Creates a NEW SentinelTrace account via pending token flow

A successful Google OAuth callback NEVER automatically creates a SentinelTrace
account unless the user explicitly completes the registration step.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from jose import jwt

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse

from app.core.config import get_settings
from app.core.deps import CurrentUser, DbSession
from app.core.security import REFRESH_TOKEN_COOKIE_NAME
from app.schemas.auth import (
    GoogleOAuthURLResponse,
    GoogleRegistrationRequest,
    LoginRequest,
    TokenResponse,
    UserRegisterRequest,
    UserResponse,
    UserProfileUpdateRequest,
)
from app.services.auth_service import (
    authenticate_user,
    logout_user,
    logout_all_user,
    register_user,
    rotate_refresh_token,
    login_google_user,
    create_google_pending_token,
    register_google_user,
    create_oauth_state,
    validate_and_consume_oauth_state,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()

# Valid intent values for Google OAuth
_VALID_INTENTS = {"login", "register"}


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    payload: UserRegisterRequest,
    db: DbSession,
    request: Request,
):
    """Register a new local user account."""
    user = await register_user(db, payload, request)
    return user


@router.post("/login", response_model=TokenResponse)
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


@router.post("/refresh", response_model=TokenResponse)
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


@router.patch("/me", response_model=UserResponse)
@router.put("/me", response_model=UserResponse)
@router.post("/me", response_model=UserResponse)
async def update_me(
    payload: UserProfileUpdateRequest,
    db: DbSession,
    current_user: CurrentUser,
):
    """Update current user's profile (full_name, avatar_url) in PostgreSQL database."""
    if payload.full_name is not None:
        current_user.full_name = payload.full_name
    if payload.avatar_url is not None:
        current_user.avatar_url = payload.avatar_url
    await db.commit()
    await db.refresh(current_user)
    return current_user


@router.get("/events-ticket")
async def get_events_ticket(current_user: CurrentUser):
    """Generate a short-lived, single-use ticket for SSE authentication."""
    expire = datetime.now(timezone.utc) + timedelta(seconds=60)
    to_encode = {"sub": str(current_user.id), "type": "sse", "exp": expire}
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return {"ticket": encoded_jwt}


# ── Google OAuth ──────────────────────────────────────────────────────────────

@router.get("/google", response_model=GoogleOAuthURLResponse)
async def google_oauth_start(
    db: DbSession,
    response: Response,
    intent: str = Query(default="login", description="OAuth intent: 'login' or 'register'"),
):
    """
    Generate the Google OAuth 2.0 authorization URL and secure state.
    Binds the state to a browser_nonce stored in an HttpOnly, Lax cookie.

    intent=login   → Only logs in EXISTING SentinelTrace accounts
    intent=register → Initiates registration flow for NEW accounts
    """
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        raise HTTPException(
            status.HTTP_501_NOT_IMPLEMENTED,
            "Google OAuth is not configured on this server",
        )

    # Validate intent
    if intent not in _VALID_INTENTS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Invalid intent '{intent}'. Must be one of: {list(_VALID_INTENTS)}"
        )

    from authlib.integrations.httpx_client import AsyncOAuth2Client

    state_nonce = secrets.token_urlsafe(32)
    browser_nonce = secrets.token_urlsafe(32)
    
    # Store state in DB (bound to browser nonce)
    await create_oauth_state(db, state_nonce, browser_nonce)

    client = AsyncOAuth2Client(
        client_id=settings.GOOGLE_CLIENT_ID,
        redirect_uri=settings.GOOGLE_REDIRECT_URI,
        scope="openid email profile",  # ONLY identity scopes
    )
    auth_url, _ = client.create_authorization_url(
        "https://accounts.google.com/o/oauth2/v2/auth",
        state=state_nonce,
        access_type="offline",
        prompt="consent",
    )
    
    # Encode intent into state cookie (safe — state is also in DB)
    response.set_cookie(
        key="st_oauth_nonce",
        value=browser_nonce,
        httponly=True,
        secure=settings.APP_ENV == "production",
        samesite="lax",
        max_age=600,  # 10 minutes
        path="/",
    )
    response.set_cookie(
        key="st_oauth_intent",
        value=intent,
        httponly=True,
        secure=settings.APP_ENV == "production",
        samesite="lax",
        max_age=600,
        path="/",
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

    STRICT SEPARATION:
    - If ExternalIdentity exists → login → redirect /login?google_auth=success
    - If account is LOCAL → collision → redirect /login?error=account_exists
    - If unknown identity + intent=login → redirect /login?error=google_not_registered
    - If unknown identity + intent=register → issue pending token → redirect /login?google_pending=<token>
    """
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, "Google OAuth not configured")

    frontend_url = settings.FRONTEND_URL or "http://localhost:5173"

    # 1. Validate State Binding
    browser_nonce = request.cookies.get("st_oauth_nonce")
    intent = request.cookies.get("st_oauth_intent", "login")  # Default to login for safety

    if not browser_nonce:
        return RedirectResponse(
            url=f"{frontend_url}/login?error=google_auth_failed&reason=cookie_missing",
            status_code=status.HTTP_302_FOUND,
        )

    # Validate intent from cookie (not URL params — URL params can be tampered)
    if intent not in _VALID_INTENTS:
        intent = "login"  # Safe default

    # 2. Consume State from DB (single-use)
    try:
        await validate_and_consume_oauth_state(db, state, browser_nonce)
    except HTTPException:
        response.delete_cookie("st_oauth_nonce", path="/", samesite="lax")
        response.delete_cookie("st_oauth_intent", path="/", samesite="lax")
        return RedirectResponse(
            url=f"{frontend_url}/login?error=google_auth_failed&reason=state_invalid",
            status_code=status.HTTP_302_FOUND,
        )

    # Clear cookies
    response.delete_cookie("st_oauth_nonce", path="/", samesite="lax")
    response.delete_cookie("st_oauth_intent", path="/", samesite="lax")

    try:
        from authlib.integrations.httpx_client import AsyncOAuth2Client
        from google.oauth2 import id_token as google_id_token
        from google.auth.transport import requests as google_requests

        # 3. Exchange Authorization Code for Tokens
        client = AsyncOAuth2Client(
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
            redirect_uri=settings.GOOGLE_REDIRECT_URI,
        )
        token_data = await client.fetch_token(
            "https://oauth2.googleapis.com/token",
            code=code,
        )

        # 4. Verify ID Token cryptographically via Google's JWKS
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

        # Raw OAuth tokens are discarded immediately after verification
        # id_info now contains: sub, email, email_verified, name, picture

        # 5. Attempt login for existing identity
        redirect_response = RedirectResponse(
            url=f"{frontend_url}/login?google_auth=success",
            status_code=status.HTTP_302_FOUND,
        )

        token_result = await login_google_user(
            db, id_info, request, redirect_response, intent=intent
        )

        if token_result is not None:
            # ── CASE A: Existing Google identity → LOGIN ──
            # login_google_user already set the refresh cookie on redirect_response
            await db.commit()
            return redirect_response

        # ── CASE C: Unknown Google identity ──
        email = id_info.get("email", "")
        name = id_info.get("name", "")

        if intent == "login":
            # User tried to LOGIN with an unregistered Google account
            # Do NOT create account, do NOT issue JWT
            await db.commit()
            return RedirectResponse(
                url=f"{frontend_url}/login?error=google_not_registered&email={email}",
                status_code=status.HTTP_302_FOUND,
            )
        else:
            # intent == "register" → Issue pending token and redirect to registration
            pending_token, _ = await create_google_pending_token(db, id_info)
            await db.commit()

            import urllib.parse
            encoded_name = urllib.parse.quote(name)
            encoded_email = urllib.parse.quote(email)
            return RedirectResponse(
                url=f"{frontend_url}/login?google_pending={pending_token}&email={encoded_email}&name={encoded_name}",
                status_code=status.HTTP_302_FOUND,
            )

    except HTTPException as e:
        await db.rollback()
        error_code = "google_auth_failed"
        if e.status_code == 409:
            error_code = "account_exists"
        return RedirectResponse(
            url=f"{frontend_url}/login?error={error_code}",
            status_code=status.HTTP_302_FOUND,
        )
    except Exception as e:
        await db.rollback()
        import logging
        logging.getLogger("sentineltrace.auth").error(f"Google callback error: {e}")
        return RedirectResponse(
            url=f"{frontend_url}/login?error=google_auth_failed",
            status_code=status.HTTP_302_FOUND,
        )


@router.post("/google/complete-registration", response_model=TokenResponse)
async def google_complete_registration(
    payload: GoogleRegistrationRequest,
    db: DbSession,
    request: Request,
    response: Response,
):
    """
    Complete Google registration using a pending token.

    This is the ONLY endpoint that creates a new SentinelTrace account for
    a Google identity. The pending token must:
    - Be signed by SentinelTrace's JWT secret
    - Have type='google_pending' (NOT 'access' — cannot access protected endpoints)
    - Not be expired (5 minute TTL)
    - Have a server-side nonce that has not been consumed

    On success: creates User, ExternalIdentity, Workspace, issues real JWT.
    On failure: full rollback, no partial account created.
    """
    return await register_google_user(db, payload.pending_token, request, response)
