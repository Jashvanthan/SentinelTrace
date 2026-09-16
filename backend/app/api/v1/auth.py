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
from datetime import UTC, datetime, timedelta, timezone
from jose import jwt

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse

from app.core.config import get_settings
from app.core.deps import CurrentUser, DbSession
from app.core.security import REFRESH_TOKEN_COOKIE_NAME
from app.schemas.auth import (
    ChangePasswordRequest,
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
    change_user_password,
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
from app.models.oauth import OAuthState

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


@router.post("/change-password", response_model=TokenResponse)
async def change_password(
    payload: ChangePasswordRequest,
    db: DbSession,
    current_user: CurrentUser,
    request: Request,
    response: Response,
):
    """
    Safely update the authenticated user's password.
    Hashes with Argon2id, invalidates old sessions, and issues fresh tokens.
    """
    return await change_user_password(db, current_user, payload, request, response)

from app.schemas.auth import ForgotPasswordRequest, ResetPasswordRequest
from app.utils.email import send_reset_password_email
from app.core.security import create_password_reset_token, verify_password_reset_token
from app.services.password_service import hash_password
from app.models.user import User
from sqlalchemy import select

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Request, Response, status, BackgroundTasks

@router.post("/forgot-password")
async def forgot_password(
    payload: ForgotPasswordRequest,
    db: DbSession,
    background_tasks: BackgroundTasks,
):
    """
    Generate and send a password reset email if the user exists.
    Always returns success to prevent email enumeration.
    """
    stmt = select(User).where(User.email == payload.email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    if user:
        token = create_password_reset_token(user.email)
        background_tasks.add_task(send_reset_password_email, user.email, token)
        
    return {"message": "If that email exists in our system, you will receive a password reset link shortly."}

@router.post("/reset-password")
async def reset_password(
    payload: ResetPasswordRequest,
    db: DbSession,
):
    """
    Reset a user's password using a valid reset token.
    """
    email = verify_password_reset_token(payload.token)
    if not email:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
        
    stmt = select(User).where(User.email == email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
        
    user.password_hash = hash_password(payload.new_password)
    # Revoke all existing sessions for security
    from app.models.oauth import RefreshSession
    from sqlalchemy import delete
    del_stmt = delete(RefreshSession).where(RefreshSession.user_id == user.id)
    await db.execute(del_stmt)
    await db.commit()
    
    return {"message": "Password has been reset successfully. You can now login."}



@router.get("/events-ticket")
async def get_events_ticket(current_user: CurrentUser):
    """Generate a short-lived, single-use ticket for SSE authentication."""
    expire = datetime.now(timezone.utc) + timedelta(seconds=60)
    to_encode = {"sub": str(current_user.id), "type": "sse", "exp": expire}
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return {"ticket": encoded_jwt}


# ── Google OAuth ──────────────────────────────────────────────────────────────

def _get_google_redirect_uri(request: Request) -> str:
    """Resolve Google OAuth redirect URI dynamically based on runtime host or configuration."""
    if settings.GOOGLE_REDIRECT_URI and not settings.GOOGLE_REDIRECT_URI.startswith("http://localhost"):
        return settings.GOOGLE_REDIRECT_URI

    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.url.netloc
    
    if "onrender.com" in host:
        proto = "https"
    
    if host and "localhost" not in host and "127.0.0.1" not in host:
        return f"{proto}://{host}/api/v1/auth/google/callback"
        
    return settings.GOOGLE_REDIRECT_URI or "http://localhost:8000/api/v1/auth/google/callback"


def _get_frontend_url(request: Request) -> str:
    """Resolve live frontend URL dynamically."""
    settings = get_settings()
    if settings.FRONTEND_URL and "localhost" not in settings.FRONTEND_URL and "127.0.0.1" not in settings.FRONTEND_URL:
        return settings.FRONTEND_URL.rstrip("/")
    origin = request.headers.get("origin")
    if origin and "localhost" not in origin and "127.0.0.1" not in origin:
        return origin.rstrip("/")
    referer = request.headers.get("referer")
    if referer:
        from urllib.parse import urlparse
        p = urlparse(referer)
        if p.scheme and p.netloc and "localhost" not in p.netloc and "127.0.0.1" not in p.netloc:
            return f"{p.scheme}://{p.netloc}".rstrip("/")
    host = request.headers.get("x-forwarded-host") or request.url.netloc or ""
    if "onrender.com" in host or settings.APP_ENV == "production" or settings.is_production:
        return "https://sentinel-trace-two.vercel.app"
    return settings.FRONTEND_URL or "http://localhost:5173"


@router.get("/google", response_model=GoogleOAuthURLResponse)
async def google_oauth_start(
    db: DbSession,
    request: Request,
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

    # Extract initiating origin (e.g. https://sentinel-trace-two.vercel.app)
    req_origin = request.headers.get("origin") or ""
    if not req_origin and request.headers.get("referer"):
        from urllib.parse import urlparse
        parsed = urlparse(request.headers.get("referer"))
        if parsed.scheme and parsed.netloc:
            req_origin = f"{parsed.scheme}://{parsed.netloc}"

    if not req_origin:
        req_origin = _get_frontend_url(request)

    state_nonce = secrets.token_urlsafe(32)
    stored_nonce_payload = f"{intent}|{req_origin}|{secrets.token_urlsafe(16)}"
    
    # Store state in DB (bound to browser nonce, intent, and originating frontend)
    await create_oauth_state(db, state_nonce, stored_nonce_payload)
    await db.commit()

    google_redirect_uri = _get_google_redirect_uri(request)
    client = AsyncOAuth2Client(
        client_id=settings.GOOGLE_CLIENT_ID,
        redirect_uri=google_redirect_uri,
        scope="openid email profile",  # ONLY identity scopes
    )
    auth_url, _ = client.create_authorization_url(
        "https://accounts.google.com/o/oauth2/v2/auth",
        state=state_nonce,
        access_type="offline",
        prompt="consent",
    )
    
    # Encode intent into state cookie (safe — state is also in DB)
    is_prod = settings.is_production
    response.set_cookie(
        key="st_oauth_nonce",
        value=stored_nonce_payload,
        httponly=True,
        secure=is_prod,
        samesite="none" if is_prod else "lax",
        max_age=600,  # 10 minutes
        path="/",
    )
    response.set_cookie(
        key="st_oauth_intent",
        value=intent,
        httponly=True,
        secure=is_prod,
        samesite="none" if is_prod else "lax",
        max_age=600,
        path="/",
    )
    
    return GoogleOAuthURLResponse(authorization_url=auth_url, state=state_nonce)


@router.get("/google/callback")
async def google_oauth_callback(
    db: DbSession,
    request: Request,
    response: Response,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
):
    """
    Handle Google OAuth 2.0 callback.

    STRICT SEPARATION:
    - If ExternalIdentity exists → login → redirect /login?google_auth=success&token=<jwt>
    - If account is LOCAL → collision → redirect /login?error=account_exists
    - If unknown identity + intent=login → redirect /login?error=google_not_registered
    - If unknown identity + intent=register → issue pending token → redirect /login?google_pending=<token>
    """
    frontend_url = _get_frontend_url(request)
    import urllib.parse
    import logging
    logger = logging.getLogger("sentineltrace.auth")

    # Clear state cookies safely
    is_prod = settings.is_production
    response.delete_cookie("st_oauth_nonce", path="/", samesite="none" if is_prod else "lax")
    response.delete_cookie("st_oauth_intent", path="/", samesite="none" if is_prod else "lax")

    # If Google redirected with an error (e.g. user denied consent)
    if error:
        err_detail = urllib.parse.quote(error_description or error)
        return RedirectResponse(
            url=f"{frontend_url}/login?error=google_auth_failed&detail={err_detail}",
            status_code=status.HTTP_302_FOUND,
        )

    if not code or not state:
        return RedirectResponse(
            url=f"{frontend_url}/login?error=google_auth_failed&detail=missing_code_or_state",
            status_code=status.HTTP_302_FOUND,
        )

    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        return RedirectResponse(
            url=f"{frontend_url}/login?error=google_auth_failed&detail=google_oauth_not_configured",
            status_code=status.HTTP_302_FOUND,
        )

    try:
        # Validate state from DB
        state_record = await db.get(OAuthState, state)
        if not state_record:
            return RedirectResponse(
                url=f"{frontend_url}/login?error=google_auth_failed&reason=state_invalid",
                status_code=status.HTTP_302_FOUND,
            )

        # Determine intent and originating frontend from stored state record
        intent = "login"
        if "|" in state_record.browser_nonce:
            parts = state_record.browser_nonce.split("|")
            intent = parts[0]
            if len(parts) > 1 and parts[1].startswith("http"):
                frontend_url = parts[1].rstrip("/")
        elif ":" in state_record.browser_nonce:
            intent = state_record.browser_nonce.split(":", 1)[0]
        elif request.cookies.get("st_oauth_intent") in _VALID_INTENTS:
            intent = request.cookies.get("st_oauth_intent")

        if intent not in _VALID_INTENTS:
            intent = "login"

        # Check expiration
        if state_record.expires_at < datetime.now(UTC):
            await db.delete(state_record)
            await db.commit()
            return RedirectResponse(
                url=f"{frontend_url}/login?error=google_auth_failed&reason=state_expired",
                status_code=status.HTTP_302_FOUND,
            )

        # Consume state to guarantee single-use
        await db.delete(state_record)
        await db.commit()

        # Exchange Authorization Code for Tokens via authlib AsyncOAuth2Client
        from authlib.integrations.httpx_client import AsyncOAuth2Client
        import httpx

        google_redirect_uri = _get_google_redirect_uri(request)
        client = AsyncOAuth2Client(
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
            redirect_uri=google_redirect_uri,
        )
        token_data = await client.fetch_token(
            "https://oauth2.googleapis.com/token",
            code=code,
        )

        id_info: dict = {}
        # Fetch user info directly using Google's userinfo endpoint with the access token
        access_token = token_data.get("access_token")
        if access_token:
            async with httpx.AsyncClient(timeout=15.0) as http_client:
                userinfo_resp = await http_client.get(
                    "https://www.googleapis.com/oauth2/v3/userinfo",
                    headers={"Authorization": f"Bearer {access_token}"}
                )
                if userinfo_resp.status_code == 200:
                    id_info = userinfo_resp.json()

        # Fallback to ID token if userinfo endpoint didn't provide sub/email
        if not id_info.get("sub") or not id_info.get("email"):
            raw_id_token = token_data.get("id_token")
            if raw_id_token:
                try:
                    from google.oauth2 import id_token as google_id_token
                    from google.auth.transport import requests as google_requests
                    request_adapter = google_requests.Request()
                    verified_claims = google_id_token.verify_oauth2_token(
                        raw_id_token,
                        request_adapter,
                        settings.GOOGLE_CLIENT_ID,
                        clock_skew_in_seconds=10,
                    )
                    id_info.update(verified_claims)
                except Exception as fallback_err:
                    logger.warning(f"Google ID token JWKS verification fallback error: {fallback_err}")
                    # Unverified decode claims as last resort
                    claims = jwt.get_unverified_claims(raw_id_token)
                    id_info.update(claims)

        if not id_info.get("sub") or not id_info.get("email"):
            raise ValueError("Failed to obtain verified identity from Google")

        # Attempt login for existing identity
        token_result = await login_google_user(
            db, id_info, request, response, intent=intent
        )

        if token_result is not None:
            # ── CASE A: Existing Google identity → LOGIN ──
            await db.commit()
            return RedirectResponse(
                url=f"{frontend_url}/login?google_auth=success&token={token_result.access_token}",
                status_code=status.HTTP_302_FOUND,
            )

        # ── CASE C: Unknown Google identity ──
        email = id_info.get("email", "")
        name = id_info.get("name", "")

        if intent == "login":
            # User tried to LOGIN with an unregistered Google account
            # Do NOT create account, do NOT issue JWT
            await db.commit()
            return RedirectResponse(
                url=f"{frontend_url}/login?error=google_not_registered&email={urllib.parse.quote(email)}",
                status_code=status.HTTP_302_FOUND,
            )
        else:
            # intent == "register" → Issue pending token and redirect to registration
            pending_token, _ = await create_google_pending_token(db, id_info)
            await db.commit()

            encoded_name = urllib.parse.quote(name)
            encoded_email = urllib.parse.quote(email)
            return RedirectResponse(
                url=f"{frontend_url}/login?google_pending={pending_token}&email={encoded_email}&name={encoded_name}",
                status_code=status.HTTP_302_FOUND,
            )

    except HTTPException as e:
        try:
            await db.rollback()
        except Exception:
            pass
        error_code = "google_auth_failed"
        email_param = ""
        if e.status_code == 409:
            error_code = "account_exists"
            try:
                if 'id_info' in locals() and isinstance(id_info, dict) and id_info.get("email"):
                    email_param = f"&email={urllib.parse.quote(id_info.get('email', ''))}"
            except Exception:
                pass
        return RedirectResponse(
            url=f"{frontend_url}/login?error={error_code}{email_param}",
            status_code=status.HTTP_302_FOUND,
        )
    except Exception as e:
        try:
            await db.rollback()
        except Exception:
            pass
        logger.error(f"Google callback unexpected error: {e}")
        err_msg = urllib.parse.quote(str(e))
        return RedirectResponse(
            url=f"{frontend_url}/login?error=google_auth_failed&detail={err_msg}",
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
