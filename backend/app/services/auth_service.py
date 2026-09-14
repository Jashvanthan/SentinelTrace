"""
SentinelTrace Backend — Auth Service

Handles:
- User registration and login
- Refresh token rotation with family revocation
- Google OAuth token exchange — strictly separated login vs registration
- Audit logging for auth events

Google OAuth security model:
  - login_google_user()         → only logs in EXISTING linked identities
  - create_google_pending_token() → issues short-lived pending token for unknown identities
  - validate_google_pending_token() → verifies + single-use nonce consumption
  - register_google_user()      → creates user ONLY after validated pending token
"""
from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request, Response, status
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.password_service import (
    DUMMY_ARGON2_HASH,
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
from app.models.audit_log import AuditLog  # noqa: F401
from app.models.refresh_session import RefreshSession
from app.services.audit_service import write_audit_log
from app.models.user import AuthProvider, User, UserRole
from app.models.oauth import ExternalIdentity, OAuthState
from app.models.google_pending import GooglePendingNonce
from app.models.workspace import Workspace, WorkspaceMember
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    TokenResponse,
    UserRegisterRequest,
    UserResponse,
)

settings = get_settings()
logger = get_logger("sentineltrace.auth")

# Pending token TTL (seconds)
_PENDING_TOKEN_TTL = 5 * 60  # 5 minutes


# ── Registration ──────────────────────────────────────────────────────────────

async def register_user(
    db: AsyncSession,
    payload: UserRegisterRequest,
    request: Request,
) -> User:
    """Register a new local user. Raises 409 if email already exists."""

    normalized_email = payload.email.strip().lower()
    existing = await db.scalar(select(User).where(User.email == normalized_email))
    if existing:
        await write_audit_log(
            db,
            action="REGISTER_FAILED_DUPLICATE",
            user_id=None,
            request=request,
            details={"email": normalized_email},
            outcome="FAILURE",
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists",
        )

    try:
        user = User(
            email=normalized_email,
            full_name=payload.full_name.strip() if payload.full_name else normalized_email,
            password_hash=hash_password(payload.password),
            role=UserRole.ANALYST,
            auth_provider=AuthProvider.LOCAL,
        )
        db.add(user)
        await db.flush()

        # Automatically create default primary workspace for the user
        ws_slug = f"workspace-{str(uuid.uuid4())[:8]}"
        default_ws = Workspace(
            name="Primary SOC Workspace",
            slug=ws_slug,
            owner_id=user.id,
        )
        db.add(default_ws)
        await db.flush()

        member = WorkspaceMember(
            workspace_id=default_ws.id,
            user_id=user.id,
            role="owner",
        )
        db.add(member)
        await db.flush()

        await write_audit_log(
            db,
            action="USER_REGISTERED",
            user_id=user.id,
            request=request,
            outcome="SUCCESS",
        )
        await db.commit()
        await db.refresh(user)
        logger.info("user_registered", user_id=str(user.id), email=user.email)
        return user
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists",
        )
    except Exception as e:
        await db.rollback()
        logger.error("user_registration_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to complete registration",
        )


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
    if user is None or not verify_password(payload.password, user.password_hash or DUMMY_ARGON2_HASH):
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


# ── Password Change ───────────────────────────────────────────────────────────

async def change_user_password(
    db: AsyncSession,
    user: User,
    payload: ChangePasswordRequest,
    request: Request,
    response: Response,
) -> TokenResponse:
    """
    Safely update user's password:
    1. Validates current password against Argon2id hash.
    2. Validates new password length & complexity.
    3. Hashes new password with Argon2id.
    4. Revokes all prior refresh sessions to force re-authentication on other devices.
    5. Issues fresh access and refresh tokens.
    """
    if user.auth_provider != AuthProvider.LOCAL:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Cannot change password for an external {user.auth_provider} account.",
        )

    if not verify_password(payload.current_password, user.password_hash):
        await write_audit_log(
            db,
            action="CHANGE_PASSWORD_FAILED",
            user_id=user.id,
            request=request,
            outcome="FAILURE",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    # Hash new password with Argon2id
    user.password_hash = hash_password(payload.new_password)
    user.updated_at = datetime.now(UTC)

    # Invalidate all existing refresh sessions for this user
    await logout_all_user(db, user.id, response)

    # Issue fresh tokens for the current session
    access_token = create_access_token(str(user.id), user.email, user.role.value)
    raw_refresh, _ = await _issue_refresh_token(db, user, request)
    set_refresh_token_cookie(response, raw_refresh)

    await write_audit_log(
        db,
        action="CHANGE_PASSWORD_SUCCESS",
        user_id=user.id,
        request=request,
        outcome="SUCCESS",
    )
    await db.commit()
    await db.refresh(user)
    logger.info("password_changed_successfully", user_id=str(user.id))

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


# ── Google OAuth State ────────────────────────────────────────────────────────

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


# ── Google OAuth — Login (EXISTING accounts only) ─────────────────────────────

async def login_google_user(
    db: AsyncSession,
    id_info: dict,
    request: Request,
    response: Response,
    intent: str = "login",
) -> TokenResponse | None:
    """
    Attempt to log in a Google-identified user.

    Returns TokenResponse if:
    - ExternalIdentity(google_sub) already exists → login

    Returns None if:
    - No ExternalIdentity exists (caller should issue pending token)

    Raises HTTPException if:
    - Email belongs to a LOCAL account (cannot auto-link)
    - Account is disabled
    - Google claims are invalid

    NEVER creates a new user or workspace.
    NEVER issues tokens for unknown Google identities.
    """
    google_sub = id_info.get("sub")
    email = id_info.get("email", "").lower()
    email_verified = id_info.get("email_verified", False)

    if not google_sub or not email:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid Google ID token claims")
        
    if not email_verified:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Google email is not verified")

    # Step 1: Check for existing ExternalIdentity (the correct, stable link)
    ext_id = await db.scalar(
        select(ExternalIdentity).where(
            ExternalIdentity.provider == "google",
            ExternalIdentity.provider_subject == google_sub
        )
    )

    if ext_id:
        if intent == "register":
            await write_audit_log(
                db,
                action="GOOGLE_REGISTER_COLLISION_EXISTING_USER",
                user_id=ext_id.user_id,
                request=request,
                details={"email": email, "intent": intent},
                outcome="FAILURE",
            )
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "This Google account is already registered with SentinelTrace. Please sign in instead.",
            )

        # ── CASE A: Existing Google-linked account → LOGIN ──
        user = await db.get(User, ext_id.user_id)
        if not user or not user.is_active:
            await write_audit_log(db, action="GOOGLE_LOGIN_FAILED_DISABLED", user_id=ext_id.user_id, request=request, outcome="FAILURE")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User account is disabled")
        
        user.avatar_url = id_info.get("picture", user.avatar_url)
        user.last_login_at = datetime.now(UTC)
        
        access_token = create_access_token(str(user.id), user.email, user.role.value)
        raw_refresh, _ = await _issue_refresh_token(db, user, request)
        set_refresh_token_cookie(response, raw_refresh)
        
        await write_audit_log(db, action="GOOGLE_LOGIN_SUCCESS", user_id=user.id, request=request)
        logger.info("google_login_success", user_id=str(user.id))
        return TokenResponse(
            access_token=access_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=UserResponse.model_validate(user),
        )

    # Step 2: No ExternalIdentity. Check email collision with LOCAL or existing accounts.
    existing_user = await db.scalar(select(User).where(User.email == email))
    if existing_user:
        if existing_user.auth_provider == AuthProvider.LOCAL or intent == "register":
            # ── CASE B: Email exists as LOCAL account or intent is register → block ──
            await write_audit_log(
                db, action="GOOGLE_ACCOUNT_COLLISION",
                user_id=existing_user.id,
                request=request,
                details={"email": email, "intent": intent},
                outcome="FAILURE",
            )
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "An account with this email already exists. Please sign in using your existing account."
            )
        # GOOGLE provider but no ExternalIdentity record (migration edge case)
        # Re-link the ExternalIdentity and login
        logger.warning("google_identity_missing_relink", email=email)
        new_ext_id = ExternalIdentity(
            user_id=existing_user.id,
            provider="google",
            provider_subject=google_sub,
            email=email,
        )
        db.add(new_ext_id)
        existing_user.last_login_at = datetime.now(UTC)
        access_token = create_access_token(str(existing_user.id), existing_user.email, existing_user.role.value)
        raw_refresh, _ = await _issue_refresh_token(db, existing_user, request)
        set_refresh_token_cookie(response, raw_refresh)
        await write_audit_log(db, action="GOOGLE_LOGIN_SUCCESS", user_id=existing_user.id, request=request)
        return TokenResponse(
            access_token=access_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=UserResponse.model_validate(existing_user),
        )

    # ── CASE C: Brand new Google identity — caller must issue pending token ──
    await write_audit_log(
        db, action="GOOGLE_LOGIN_UNKNOWN_ACCOUNT",
        user_id=None,
        request=request,
        details={"email": email, "intent": intent},
        outcome="PENDING",
    )
    return None  # Caller issues pending token and redirects to registration


# ── Google Pending Token (bridge between OAuth verify and registration) ────────

async def create_google_pending_token(
    db: AsyncSession,
    id_info: dict,
) -> tuple[str, str]:
    """
    Create a short-lived signed pending token + persist a single-use nonce.

    Returns (signed_jwt, nonce)
    The JWT contains type='google_pending' so it is REJECTED by access token validators.
    The nonce is persisted in the DB — it must be consumed before registration proceeds.
    TTL: 5 minutes.
    """
    google_sub = id_info.get("sub")
    email = id_info.get("email", "").lower()
    full_name = id_info.get("name", email)
    picture = id_info.get("picture")

    nonce = secrets.token_urlsafe(32)
    expires_at = datetime.now(UTC) + timedelta(seconds=_PENDING_TOKEN_TTL)

    # Persist nonce for single-use enforcement
    pending_nonce = GooglePendingNonce(
        nonce=nonce,
        google_sub=google_sub,
        email=email,
        full_name=full_name,
        picture=picture,
        expires_at=expires_at,
        consumed=False,
    )
    db.add(pending_nonce)
    await db.flush()

    # Sign the pending token — type=google_pending ensures it cannot access protected endpoints
    payload = {
        "token_type": "google_pending",  # CRITICAL: explicitly NOT "access"
        "sub": google_sub,
        "email": email,
        "name": full_name,
        "picture": picture,
        "nonce": nonce,
        "iat": datetime.now(UTC).timestamp(),
        "exp": expires_at.timestamp(),
    }
    pending_jwt = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    
    logger.info("google_pending_token_created", email=email)
    return pending_jwt, nonce


async def validate_google_pending_token(
    db: AsyncSession,
    pending_token: str,
    request: Request,
) -> dict:
    """
    Validate a Google pending registration token.

    Steps:
    1. Verify JWT signature and expiration
    2. Verify token_type == 'google_pending'
    3. Extract nonce
    4. Look up nonce in DB
    5. Verify nonce not expired
    6. Atomically mark nonce as consumed (prevents replay)
    7. Verify google_sub matches

    Returns the validated id_info dict: {google_sub, email, full_name, picture}
    Raises HTTPException on any failure.
    """
    # Step 1 & 2: Verify signature, expiry, and type
    try:
        payload = jwt.decode(
            pending_token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
    except JWTError as e:
        await write_audit_log(
            db, action="GOOGLE_PENDING_TOKEN_REJECTED",
            user_id=None, request=request,
            details={"reason": "jwt_invalid"},
            outcome="FAILURE",
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired registration token")

    if payload.get("token_type") != "google_pending":
        await write_audit_log(
            db, action="GOOGLE_PENDING_TOKEN_REJECTED",
            user_id=None, request=request,
            details={"reason": "wrong_token_type", "got": payload.get("token_type")},
            outcome="FAILURE",
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid registration token type")

    google_sub = payload.get("sub")
    email = payload.get("email", "").lower()
    nonce = payload.get("nonce")

    if not google_sub or not email or not nonce:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Malformed registration token")

    # Step 3-7: Find, validate, and atomically consume nonce
    pending_nonce = await db.scalar(
        select(GooglePendingNonce).where(GooglePendingNonce.nonce == nonce)
    )

    if not pending_nonce:
        await write_audit_log(
            db, action="GOOGLE_PENDING_TOKEN_REJECTED",
            user_id=None, request=request,
            details={"reason": "nonce_not_found"},
            outcome="FAILURE",
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Registration session not found or already used")

    if pending_nonce.consumed:
        await write_audit_log(
            db, action="GOOGLE_PENDING_TOKEN_REJECTED",
            user_id=None, request=request,
            details={"reason": "nonce_consumed"},
            outcome="FAILURE",
        )
        raise HTTPException(status.HTTP_409_CONFLICT, "This Google registration link has already been used")

    if pending_nonce.expires_at < datetime.now(UTC):
        await write_audit_log(
            db, action="GOOGLE_PENDING_TOKEN_EXPIRED",
            user_id=None, request=request,
            details={"email": email},
            outcome="FAILURE",
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Your Google registration session has expired. Please try again.")

    if not secrets.compare_digest(pending_nonce.google_sub, google_sub):
        await write_audit_log(
            db, action="GOOGLE_PENDING_TOKEN_REJECTED",
            user_id=None, request=request,
            details={"reason": "sub_mismatch"},
            outcome="FAILURE",
        )
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Registration token identity mismatch")

    # Atomically consume the nonce — any concurrent call will now fail
    pending_nonce.consumed = True
    await db.flush()

    return {
        "sub": google_sub,
        "email": email,
        "name": pending_nonce.full_name,
        "picture": pending_nonce.picture,
    }


# ── Google Registration (NEW accounts only) ───────────────────────────────────

async def register_google_user(
    db: AsyncSession,
    pending_token: str,
    request: Request,
    response: Response,
) -> TokenResponse:
    """
    Complete Google registration after pending token validation.

    Full transactional flow:
    1. Validate pending token + consume nonce (single-use)
    2. Re-check ExternalIdentity doesn't already exist (concurrent safety)
    3. Re-check email doesn't already exist (concurrent safety)
    4. Create User (Google provider, no password)
    5. Create ExternalIdentity
    6. Create default Workspace
    7. Create WorkspaceMember (owner)
    8. Audit: GOOGLE_REGISTRATION_SUCCESS
    9. Commit
    10. Issue real JWT + refresh cookie

    On any failure: full ROLLBACK — no partial account left.
    """
    try:
        # Step 1: Validate + consume nonce
        id_info = await validate_google_pending_token(db, pending_token, request)
        
        google_sub = id_info["sub"]
        email = id_info["email"]
        full_name = id_info["name"]
        picture = id_info.get("picture")

        # Step 2: Double-check ExternalIdentity (concurrent registration guard)
        existing_ext = await db.scalar(
            select(ExternalIdentity).where(
                ExternalIdentity.provider == "google",
                ExternalIdentity.provider_subject == google_sub,
            )
        )
        if existing_ext:
            # Google identity already registered — login instead
            user = await db.get(User, existing_ext.user_id)
            if user and user.is_active:
                await write_audit_log(db, action="GOOGLE_REGISTRATION_DUPLICATE", user_id=user.id, request=request, outcome="DUPLICATE")
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    "This Google account is already registered with SentinelTrace. Please sign in."
                )
            raise HTTPException(status.HTTP_409_CONFLICT, "This Google account is already registered.")

        # Step 3: Double-check email (concurrent registration guard)
        existing_email_user = await db.scalar(select(User).where(User.email == email))
        if existing_email_user:
            await write_audit_log(
                db, action="GOOGLE_REGISTRATION_DUPLICATE",
                user_id=existing_email_user.id, request=request,
                details={"reason": "email_exists"},
                outcome="DUPLICATE",
            )
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "An account with this email already exists. Please sign in."
            )

        # Step 4: Create User (Google provider, no password_hash)
        user = User(
            email=email,
            full_name=full_name,
            avatar_url=picture,
            auth_provider=AuthProvider.GOOGLE,
            is_verified=True,
            role=UserRole.ANALYST,
            password_hash=None,  # Google accounts have no password
        )
        db.add(user)
        await db.flush()

        # Step 5: Create ExternalIdentity
        ext_id = ExternalIdentity(
            user_id=user.id,
            provider="google",
            provider_subject=google_sub,
            email=email,
        )
        db.add(ext_id)
        await db.flush()

        # Step 6: Create default Workspace
        ws_slug = f"workspace-{str(uuid.uuid4())[:8]}"
        default_ws = Workspace(
            name="Primary SOC Workspace",
            slug=ws_slug,
            owner_id=user.id,
        )
        db.add(default_ws)
        await db.flush()

        # Step 7: Create WorkspaceMember
        member = WorkspaceMember(
            workspace_id=default_ws.id,
            user_id=user.id,
            role="owner",
        )
        db.add(member)
        await db.flush()

        # Step 8: Audit
        await write_audit_log(
            db, action="GOOGLE_REGISTRATION_SUCCESS",
            user_id=user.id, request=request,
            outcome="SUCCESS",
        )

        # Step 9: Commit everything atomically
        await db.commit()
        await db.refresh(user)

        # Step 10: Issue real JWT + refresh cookie
        access_token = create_access_token(str(user.id), user.email, user.role.value)
        raw_refresh, _ = await _issue_refresh_token(db, user, request)
        set_refresh_token_cookie(response, raw_refresh)
        user.last_login_at = datetime.now(UTC)

        logger.info("google_user_registered", user_id=str(user.id), email=user.email)
        return TokenResponse(
            access_token=access_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=UserResponse.model_validate(user),
        )

    except HTTPException:
        await db.rollback()
        raise
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "An account with this email or Google identity already exists."
        )
    except Exception as e:
        await db.rollback()
        logger.error("google_registration_failed", error=str(e))
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Google registration could not be completed. Please try again."
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
