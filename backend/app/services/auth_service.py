"""
SentinelTrace Backend — Auth Service

Handles:
- User registration and login
- Refresh token rotation with family revocation
- Google OAuth token exchange
- Audit logging for auth events
"""
from __future__ import annotations

import uuid
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.password_service import (
    hash_password,
    needs_rehash,
    verify_password,
)
from app.core.security import (
    clear_refresh_token_cookie,
    generate_refresh_token,
    set_refresh_token_cookie,
    create_access_token,
)
from app.models.audit_log import AuditLog
from app.models.refresh_session import RefreshSession
from app.services.audit_service import write_audit_log
from app.models.user import AuthProvider, User, UserRole
from app.models.oauth import ExternalIdentity, OAuthState
from app.schemas.auth import LoginRequest, TokenResponse, UserRegisterRequest, UserResponse

settings = get_settings()
logger = get_logger("sentineltrace.auth")


# ── Registration ──────────────────────────────────────────────────────────────

async def register_user(
    db: AsyncSession,
    payload: UserRegisterRequest,
    request: Request,
) -> User:
    """Register a new local user. Raises 409 if email already exists."""
    existing = await db.scalar(select(User).where(User.email == payload.email.lower()))
    if existing:
        # Prevent account enumeration by returning a generic 201 with the submitted info
        # The attacker thinks registration succeeded, but the real account is untouched.
        # When they try to login with this password, it will fail.
        await write_audit_log(db, action="REGISTER_FAILED_DUPLICATE", user_id=None, request=request, details={"email": payload.email})
        return User(
            id=uuid.uuid4(),
            email=payload.email.lower(),
            full_name=payload.full_name,
            role=UserRole.ANALYST,
            auth_provider=AuthProvider.LOCAL,
            is_active=True,
            is_verified=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

    user = User(
        email=payload.email.lower(),
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role=UserRole.ANALYST,
        auth_provider=AuthProvider.LOCAL,
    )
    db.add(user)
    await db.flush()

    await write_audit_log(db, action="USER_REGISTERED", user_id=user.id, request=request)
    logger.info("user_registered", user_id=str(user.id), email=user.email)
    return user


# ── Login ─────────────────────────────────────────────────────────────────────

async def authenticate_user(
    db: AsyncSession,
    payload: LoginRequest,
    request: Request,
    response: Response,
) -> TokenResponse:
    """
    Authenticate a user with email/password.
    Issues access token + stores refresh token in HttpOnly cookie.
    """
    user = await db.scalar(
        select(User).where(User.email == payload.email.lower(), User.is_active.is_(True))
    )

    # Constant-time comparison to prevent timing attacks
    dummy_hash = "$argon2id$v=19$m=65536,t=3,p=1$dummydummydummy$dummydummydummydummydummy"
    if user is None or not verify_password(payload.password, user.password_hash or dummy_hash):
        await write_audit_log(
            db, action="LOGIN_FAILED", user_id=None,
            request=request,
            details={"email": payload.email},
            outcome="FAILURE",
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    if user.auth_provider != AuthProvider.LOCAL:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"This account uses {user.auth_provider} login. Please use that method.",
        )

    # Rehash if cost parameters changed
    if user.password_hash and needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)

    access_token = create_access_token(str(user.id), user.email, user.role.value)
    raw_refresh, refresh_hash = await _issue_refresh_token(db, user, request)

    set_refresh_token_cookie(response, raw_refresh)

    user.last_login_at = datetime.now(UTC)
    await write_audit_log(db, action="LOGIN_SUCCESS", user_id=user.id, request=request)
    logger.info("user_login", user_id=str(user.id))

    return TokenResponse(
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


# ── Refresh Token Rotation ────────────────────────────────────────────────────

async def rotate_refresh_token(
    db: AsyncSession,
    raw_refresh_token: str,
    request: Request,
    response: Response,
) -> TokenResponse:
    """
    Rotate a refresh token:
    1. Find and verify the stored token
    2. If revoked → revoke entire family (token theft detected)
    3. If valid → revoke old token, issue new access + refresh tokens
    """
    token_hash = _hash_token(raw_refresh_token)
    stored: RefreshSession | None = await db.scalar(
        select(RefreshSession).where(RefreshSession.token_hash == token_hash)
    )

    if stored is None or stored.is_expired:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

    if stored.revoked:
        # Token reuse detected → revoke entire family
        logger.warning("refresh_token_reuse_detected", family_id=str(stored.family_id))
        await _revoke_token_family(db, stored.family_id)
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token reuse detected. Please log in again.")

    # Revoke the used token
    stored.revoked = True
    stored.revoked_at = datetime.now(UTC)

    user = await db.get(User, stored.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or deactivated")

    access_token = create_access_token(str(user.id), user.email, user.role.value)
    raw_new, _ = await _issue_refresh_token(db, user, request, family_id=stored.family_id)

    set_refresh_token_cookie(response, raw_new)
    return TokenResponse(
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


async def logout_user(
    db: AsyncSession,
    raw_refresh_token: str | None,
    user_id: uuid.UUID,
    response: Response,
) -> None:
    """Revoke the refresh token and clear the cookie."""
    if raw_refresh_token:
        token_hash = _hash_token(raw_refresh_token)
        stored = await db.scalar(
            select(RefreshSession).where(RefreshSession.token_hash == token_hash)
        )
        if stored and not stored.revoked:
            stored.revoked = True
            stored.revoked_at = datetime.now(UTC)

    clear_refresh_token_cookie(response)
    logger.info("user_logout", user_id=str(user_id))


async def logout_all_user(
    db: AsyncSession,
    user_id: uuid.UUID,
    response: Response,
) -> None:
    """Revoke ALL active refresh sessions for the user."""
    result = await db.execute(
        select(RefreshSession).where(
            RefreshSession.user_id == user_id,
            RefreshSession.revoked.is_(False),
        )
    )
    for session in result.scalars():
        session.revoked = True
        session.revoked_at = datetime.now(UTC)

    clear_refresh_token_cookie(response)
    logger.info("user_logout_all", user_id=str(user_id))


# ── Google OAuth ──────────────────────────────────────────────────────────────

async def create_oauth_state(db: AsyncSession, state_nonce: str, browser_nonce: str) -> None:
    """Store the OAuth state and its binding browser nonce. Expires in 10 minutes."""
    state = OAuthState(
        state=state_nonce,
        browser_nonce=browser_nonce,
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=10)
    )
    db.add(state)
    await db.flush()

async def validate_and_consume_oauth_state(db: AsyncSession, state_nonce: str, browser_nonce: str) -> None:
    """
    Validates that the state exists, is not expired, and matches the browser context.
    Immediately deletes the state to guarantee single-use.
    """
    state_record = await db.get(OAuthState, state_nonce)
    
    if not state_record:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired OAuth state")
    
    # Always delete to guarantee single-use, regardless of validation outcome
    await db.delete(state_record)
    await db.flush()

    if state_record.expires_at < datetime.now(UTC):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "OAuth state expired")
        
    if secrets.compare_digest(state_record.browser_nonce, browser_nonce) is False:
        logger.warning("oauth_browser_mismatch", state=state_nonce)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "OAuth browser context mismatch. Possible CSRF.")


async def upsert_google_user(
    db: AsyncSession,
    id_info: dict,
    request: Request,
    response: Response,
) -> TokenResponse:
    """
    Create or link a Google identity based on ID token claims.
    Enforces account collision policy (blocks merging into LOCAL accounts).
    Sets the refresh token cookie.
    """
    google_sub = id_info.get("sub")
    email = id_info.get("email", "").lower()
    email_verified = id_info.get("email_verified", False)

    if not google_sub or not email:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid Google ID token claims")
        
    if not email_verified:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Google email is not verified")

    # Check if ExternalIdentity already exists
    ext_id = await db.scalar(
        select(ExternalIdentity).where(
            ExternalIdentity.provider == "google",
            ExternalIdentity.provider_subject == google_sub
        )
    )

    if ext_id:
        # Existing linked account
        user = await db.get(User, ext_id.user_id)
        if not user or not user.is_active:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User account is disabled")
        
        user.avatar_url = id_info.get("picture", user.avatar_url)
        await write_audit_log(db, action="GOOGLE_LOGIN", user_id=user.id, request=request)
    else:
        # New Google Identity. Check for email collision.
        existing_user = await db.scalar(select(User).where(User.email == email))
        
        if existing_user:
            if existing_user.auth_provider == AuthProvider.LOCAL:
                # MANDATORY CORRECTION: DO NOT automatically merge accounts.
                await write_audit_log(db, action="GOOGLE_ACCOUNT_COLLISION", user_id=existing_user.id, request=request)
                raise HTTPException(
                    status.HTTP_409_CONFLICT, 
                    "Email already registered using password login. Please login with password."
                )
            # If it's already GOOGLE provider but missing ExternalIdentity (e.g. migration edge case)
            user = existing_user
        else:
            # Create brand new user
            user = User(
                email=email,
                full_name=id_info.get("name", email),
                avatar_url=id_info.get("picture"),
                auth_provider=AuthProvider.GOOGLE,
                is_verified=True,
                role=UserRole.ANALYST,
            )
            db.add(user)
            await db.flush()
            await write_audit_log(db, action="GOOGLE_USER_CREATED", user_id=user.id, request=request)

        # Create External Identity link
        new_ext_id = ExternalIdentity(
            user_id=user.id,
            provider="google",
            provider_subject=google_sub,
            email=email,
        )
        db.add(new_ext_id)
        await db.flush()
        await write_audit_log(db, action="GOOGLE_ACCOUNT_LINKED", user_id=user.id, request=request)

    # Issue tokens
    access_token = create_access_token(str(user.id), user.email, user.role.value)
    raw_refresh, _ = await _issue_refresh_token(db, user, request)
    set_refresh_token_cookie(response, raw_refresh)
    user.last_login_at = datetime.now(UTC)

    return TokenResponse(
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _issue_refresh_token(
    db: AsyncSession,
    user: User,
    request: Request,
    family_id: uuid.UUID | None = None,
) -> tuple[str, str]:
    raw_token, token_hash = generate_refresh_token()
    refresh_session = RefreshSession(
        user_id=user.id,
        token_hash=token_hash,
        family_id=family_id or uuid.uuid4(),
        expires_at=datetime.now(UTC) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        user_agent=request.headers.get("User-Agent"),
        ip_address=request.client.host if request.client else None,
    )
    db.add(refresh_session)
    return raw_token, token_hash


async def _revoke_token_family(db: AsyncSession, family_id: uuid.UUID) -> None:
    result = await db.execute(
        select(RefreshSession).where(
            RefreshSession.family_id == family_id,
            RefreshSession.revoked.is_(False),
        )
    )
    for token in result.scalars():
        token.revoked = True
        token.revoked_at = datetime.now(UTC)


def _hash_token(raw: str) -> str:
    import hashlib
    return hashlib.sha256(raw.encode()).hexdigest()


