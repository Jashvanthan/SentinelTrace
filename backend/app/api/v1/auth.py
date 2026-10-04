"""
SentinelTrace Backend — Auth API Router

Endpoints:
  POST /auth/register                    Register a new local user
  POST /auth/login                       Email/password login
  POST /auth/refresh                     Rotate access token via refresh cookie
  POST /auth/logout                      Revoke refresh token
  POST /auth/logout-all                  Revoke all user refresh sessions
  GET  /auth/me                          Get current user info
  PATCH/PUT/POST /auth/me                Update current user info
  POST /auth/change-password             Change user password
  POST /auth/forgot-password             Send reset password link
  POST /auth/reset-password              Reset password with token
  GET  /auth/events-ticket               Generate short-lived SSE ticket
  GET  /auth/google?intent=login|register Get Google OAuth URL
  GET  /auth/google/callback             Handle Google OAuth callback
  POST /auth/google/complete-registration Finalize Google registration
"""
from __future__ import annotations

import logging
import secrets
import urllib.parse
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Cookie,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import RedirectResponse
from jose import jwt
from sqlalchemy import delete, select

from app.core.config import get_settings
from app.core.deps import CurrentUser, DbSession
from app.core.security import (
    REFRESH_TOKEN_COOKIE_NAME,
    create_password_reset_token,
    verify_password_reset_token,
)
from app.models.oauth import OAuthState
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.schemas.auth import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    GoogleOAuthURLResponse,
    GoogleRegistrationRequest,
    LoginRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserProfileUpdateRequest,
    UserRegisterRequest,
    UserResponse,
)
from app.services.auth_service import (
    authenticate_user,
    change_user_password,
    create_google_pending_token,
    create_oauth_state,
    login_google_user,
    logout_all_user,
    logout_user,
    register_google_user,
    register_user,
    rotate_refresh_token,
)
from pydantic import BaseModel, EmailStr
from app.services.password_service import hash_password
from app.services.smtp_service import smtp_service
from app.utils.email import send_reset_password_email

logger = logging.getLogger("sentineltrace.auth")
router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()

# Valid intent values for Google OAuth
_VALID_INTENTS = {"login", "register"}


class WelcomeEmailRequest(BaseModel):
    email: EmailStr
    name: str | None = None
    workspace_name: str | None = "Personal Workspace"
    application_url: str | None = None


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    payload: UserRegisterRequest,
    db: DbSession,
    request: Request,
    background_tasks: BackgroundTasks,
) -> UserResponse:
    """Register a new local user account."""
    user = await register_user(db, payload, request)
    # Dispatch enterprise branded HTML welcome email via Gmail SMTP
    background_tasks.add_task(
        smtp_service.dispatch_welcome_email,
        email=user.email,
        name=user.full_name,
        workspace_name="Personal Workspace",
        platform_url=settings.FRONTEND_URL,
    )
    return user


@router.post("/welcome-email")
async def trigger_welcome_email(
    payload: WelcomeEmailRequest,
    background_tasks: BackgroundTasks,
):
    """
    Manually or programmatically trigger an enterprise dark-mode HTML welcome email
    via SentinelTrace's verified Gmail SMTP service.
    """
    background_tasks.add_task(
        smtp_service.dispatch_welcome_email,
        email=str(payload.email),
        name=payload.name,
        workspace_name=payload.workspace_name or "Personal Workspace",
        platform_url=payload.application_url or settings.FRONTEND_URL,
    )
    return {"status": "QUEUED", "message": f"Welcome email queued for {payload.email}"}


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    db: DbSession,
    request: Request,
    response: Response,
) -> TokenResponse:
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
) -> TokenResponse:
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
) -> None:
    """Revoke the current refresh token and clear the cookie."""
    await logout_user(db, refresh_token_cookie, current_user.id, response)


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(
    db: DbSession,
    response: Response,
    current_user: CurrentUser,
) -> None:
    """Revoke all refresh sessions for the user and clear the cookie."""
    await logout_all_user(db, current_user.id, response)


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: CurrentUser) -> UserResponse:
    """Return the currently authenticated user's profile."""
    return current_user


@router.patch("/me", response_model=UserResponse)
@router.put("/me", response_model=UserResponse)
@router.post("/me", response_model=UserResponse)
async def update_me(
    payload: UserProfileUpdateRequest,
    db: DbSession,
    current_user: CurrentUser,
) -> UserResponse:
    """Update current user's profile (full_name, avatar_url) in PostgreSQL database."""
    if payload.full_name is not None:
        current_user.full_name = payload.full_name
    if payload.avatar_url is not None:
        current_user.avatar_url = payload.avatar_url
    db.add(current_user)
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
) -> TokenResponse:
    """
    Safely update the authenticated user's password.
    Hashes with Argon2id, invalidates old sessions, and issues fresh tokens.
    """
    return await change_user_password(db, current_user, payload, request, response)


@router.post("/forgot-password")
async def forgot_password(
    payload: ForgotPasswordRequest,
    db: DbSession,
    background_tasks: BackgroundTasks,
) -> dict[str, str]:
    """
    Generate and send a password reset email if the user exists.
    Always returns success to prevent email enumeration.
    """
    email = payload.email.lower()
    stmt = select(User).where(User.email == email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user:
        logger.info(f"User {payload.email} found in database. Queuing email.")
        token = create_password_reset_token(user.email)
        background_tasks.add_task(send_reset_password_email, user.email, token)
    else:
        logger.warning(f"Forgot password requested for {payload.email}, but user does NOT exist in the database.")

    return {"message": "If that email exists in our system, you will receive a password reset link shortly."}


@router.post("/reset-password")
async def reset_password(
    payload: ResetPasswordRequest,
    db: DbSession,
) -> dict[str, str]:
    """Reset a user's password using a valid reset token."""
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
    del_stmt = delete(RefreshSession).where(RefreshSession.user_id == user.id)
    await db.execute(del_stmt)
    await db.commit()

    return {"message": "Password has been reset successfully. You can now login."}


@router.get("/events-ticket")
async def get_events_ticket(current_user: CurrentUser) -> dict[str, str]:
    """Generate a short-lived, single-use ticket for SSE authentication."""
    expire = datetime.now(timezone.utc) + timedelta(seconds=60)
    to_encode = {"sub": str(current_user.id), "type": "sse", "exp": expire}
    secret = (
        settings.JWT_SECRET.get_secret_value()
        if hasattr(settings.JWT_SECRET, "get_secret_value")
        else str(settings.JWT_SECRET)
    )
    encoded_jwt = jwt.encode(to_encode, secret, algorithm=settings.JWT_ALGORITHM)
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
    if "onrender.com" in host or settings.APP_ENV == "production" or getattr(settings, "is_production", False):
        return "https://sentinel-trace-two.vercel.app"
    return settings.FRONTEND_URL or "http://localhost:5173"


@router.get("/google", response_model=GoogleOAuthURLResponse)
async def google_oauth_start(
    db: DbSession,
    request: Request,
    response: Response,
    intent: str = Query(default="login", description="OAuth intent: 'login' or 'register'"),
) -> GoogleOAuthURLResponse:
    """
    Generate the Google OAuth 2.0 authorization URL and secure state.
    Binds the state to a browser_nonce stored in an HttpOnly, Lax cookie.
    """
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        raise HTTPException(
            status.HTTP_501_NOT_IMPLEMENTED,
            "Google OAuth is not configured on this server",
        )

    if intent not in _VALID_INTENTS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Invalid intent '{intent}'. Must be one of: {list(_VALID_INTENTS)}",
        )

    from authlib.integrations.httpx_client import AsyncOAuth2Client

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

    await create_oauth_state(db, state_nonce, stored_nonce_payload)
    await db.commit()

    google_redirect_uri = _get_google_redirect_uri(request)
    client = AsyncOAuth2Client(
        client_id=settings.GOOGLE_CLIENT_ID,
        redirect_uri=google_redirect_uri,
        scope="openid email profile",
    )
    auth_url, _ = client.create_authorization_url(
        "https://accounts.google.com/o/oauth2/v2/auth",
        state=state_nonce,
        access_type="offline",
        prompt="consent",
    )

    is_prod = getattr(settings, "is_production", False)
    response.set_cookie(
        key="st_oauth_nonce",
        value=stored_nonce_payload,
        httponly=True,
        secure=is_prod,
        samesite="none" if is_prod else "lax",
        max_age=600,
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
) -> RedirectResponse:
    """
    Handle Google OAuth 2.0 callback with strict state verification.
    """
    frontend_url = _get_frontend_url(request)

    is_prod = getattr(settings, "is_production", False)
    response.delete_cookie("st_oauth_nonce", path="/", samesite="none" if is_prod else "lax")
    response.delete_cookie("st_oauth_intent", path="/", samesite="none" if is_prod else "lax")

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
        state_record = await db.get(OAuthState, state)
        if not state_record:
            return RedirectResponse(
                url=f"{frontend_url}/login?error=google_auth_failed&reason=state_invalid",
                status_code=status.HTTP_302_FOUND,
            )

        intent = "login"
        if "|" in state_record.browser_nonce:
            parts = state_record.browser_nonce.split("|")
            intent = parts[0]
            if len(parts) > 1 and parts[1].startswith("http"):
                frontend_url = parts[1].rstrip("/")
        elif ":" in state_record.browser_nonce:
            intent = state_record.browser_nonce.split(":", 1)[0]
        elif request.cookies.get("st_oauth_intent") in _VALID_INTENTS:
            intent = request.cookies.get("st_oauth_intent") or "login"

        if intent not in _VALID_INTENTS:
            intent = "login"

        state_exp = state_record.expires_at
        if state_exp.tzinfo is None:
            state_exp = state_exp.replace(tzinfo=UTC)

        if state_exp < datetime.now(UTC):
            await db.delete(state_record)
            await db.commit()
            return RedirectResponse(
                url=f"{frontend_url}/login?error=google_auth_failed&reason=state_expired",
                status_code=status.HTTP_302_FOUND,
            )

        await db.delete(state_record)
        await db.commit()

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

        id_info: dict[str, Any] = {}
        access_token = token_data.get("access_token")
        if access_token:
            async with httpx.AsyncClient(timeout=15.0) as http_client:
                userinfo_resp = await http_client.get(
                    "https://www.googleapis.com/oauth2/v3/userinfo",
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                if userinfo_resp.status_code == 200:
                    id_info = userinfo_resp.json()

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
                    logger.warning(f"Google ID token JWKS fallback: {fallback_err}")
                    claims = jwt.get_unverified_claims(raw_id_token)
                    id_info.update(claims)

        if not id_info.get("sub") or not id_info.get("email"):
            raise ValueError("Failed to obtain verified identity from Google")

        token_result = await login_google_user(db, id_info, request, response, intent=intent)

        if token_result is not None:
            await db.commit()
            return RedirectResponse(
                url=f"{frontend_url}/login?google_auth=success&token={token_result.access_token}",
                status_code=status.HTTP_302_FOUND,
            )

        email = id_info.get("email", "")
        name = id_info.get("name", "")

        if intent == "login":
            await db.commit()
            return RedirectResponse(
                url=f"{frontend_url}/login?error=google_not_registered&email={urllib.parse.quote(email)}",
                status_code=status.HTTP_302_FOUND,
            )
        else:
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
                if "id_info" in locals() and isinstance(id_info, dict) and id_info.get("email"):
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
    background_tasks: BackgroundTasks,
) -> TokenResponse:
    """
    Complete Google registration using a pending token.
    On success: creates User, ExternalIdentity, Workspace, issues real JWT.
    """
    token_resp = await register_google_user(db, payload.pending_token, request, response)
    if token_resp and token_resp.user:
        background_tasks.add_task(
            smtp_service.dispatch_welcome_email,
            email=token_resp.user.email,
            name=token_resp.user.full_name,
            workspace_name="Personal Workspace",
            platform_url=settings.FRONTEND_URL,
        )
    return token_resp
