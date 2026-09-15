"""
SentinelTrace Backend — Integrations API
"""
from __future__ import annotations

import logging
import uuid
import json
from datetime import datetime, timezone, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import secrets
from jose import jwt

from app.core.deps import get_current_user, require_workspace_role
from app.core.security import decode_access_token
from app.db.session import get_db_session as get_db
from app.core.config import get_settings
from app.models.integrations import GmailConnection
from app.models.jobs import GmailSyncJob
from app.models.oauth import OAuthState
from app.models.user import User
from app.models.workspace import WorkspaceMember
from app.services.encryption_service import encrypt_token
from app.services.gmail_service import gmail_service
from app.services.user_service import get_user_by_id

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Gmail OAuth Connect Flow ──────────────────────────────────────────────────

async def _resolve_oauth_user(request: Request, db: AsyncSession) -> User:
    """Extract and validate user from Authorization header or ?token= query parameter."""
    auth_header = request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
    elif "token" in request.query_params:
        token = request.query_params["token"]

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated. Provide Authorization header or ?token= query parameter.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(token)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired access token") from exc

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token: missing subject")
    user = await get_user_by_id(db, uuid.UUID(user_id))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


def _get_gmail_redirect_uri(request: Request) -> str:
    """Resolve Gmail OAuth redirect URI dynamically based on runtime host or configuration."""
    settings = get_settings()
    if settings.GMAIL_REDIRECT_URI and not settings.GMAIL_REDIRECT_URI.startswith("http://localhost"):
        return settings.GMAIL_REDIRECT_URI

    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.url.netloc

    if "onrender.com" in host:
        proto = "https"

    if host and "localhost" not in host and "127.0.0.1" not in host:
        return f"{proto}://{host}/api/v1/integrations/gmail/callback"

    return settings.GMAIL_REDIRECT_URI or "http://localhost:8000/api/v1/integrations/gmail/callback"


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


@router.get("/workspaces/{workspace_id}/integrations/gmail/connect")
async def connect_gmail(
    workspace_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Initiate Gmail OAuth connection for a specific workspace.
    Supports both API requests (returns JSON with authorization_url) and browser navigation (redirects).
    """
    user = await _resolve_oauth_user(request, db)

    # Verify workspace membership and permissions
    member = await db.scalar(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == user.id,
        )
    )
    if not member:
        raise HTTPException(status_code=404, detail="Workspace not found")
    if member.role not in ["owner", "admin", "editor"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions to connect integrations")

    settings = get_settings()
    raw_nonce = secrets.token_urlsafe(16)
    state_token = secrets.token_urlsafe(32)  # 43 chars <= 128

    # Store workspace_id and user_id safely inside browser_nonce (36 + 1 + 36 + 1 + ~22 = ~96 chars <= 128)
    packed_nonce = f"{workspace_id}:{user.id}:{raw_nonce}"

    # Store OAuthState strictly adhering to the VARCHAR(128) database schema
    oauth_state = OAuthState(
        state=state_token,
        browser_nonce=packed_nonce,
        created_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
    )
    db.add(oauth_state)
    await db.commit()

    gmail_redirect_uri = _get_gmail_redirect_uri(request)
    auth_url, code_verifier = gmail_service.get_authorization_url(state=state_token, redirect_uri=gmail_redirect_uri)

    # Return JSON if client requested JSON or called via frontend API; otherwise RedirectResponse
    wants_json = "application/json" in request.headers.get("accept", "") or request.query_params.get("format") == "json"
    if wants_json:
        response = JSONResponse(content={"authorization_url": auth_url, "state": state_token})
    else:
        response = RedirectResponse(url=auth_url)

    response.set_cookie(
        "st_gmail_oauth_nonce",
        raw_nonce,
        httponly=True,
        secure=settings.APP_ENV == "production",
        samesite="lax",
        max_age=900,  # 15 minutes
        path="/",
    )
    if code_verifier:
        response.set_cookie(
            "st_gmail_code_verifier",
            code_verifier,
            httponly=True,
            secure=settings.APP_ENV == "production",
            samesite="lax",
            max_age=900,  # 15 minutes
            path="/",
        )
    return response


@router.get("/integrations/gmail/callback")
async def gmail_callback(
    request: Request,
    state: str = Query(..., description="OAuth state parameter"),
    code: str | None = Query(None, description="OAuth authorization code"),
    error: str | None = Query(None, description="OAuth error if any"),
    db: AsyncSession = Depends(get_db),
):
    """
    Handle Google OAuth callback for Gmail.
    """
    frontend_url = _get_frontend_url(request)

    if error:
        logger.warning(f"Google OAuth returned error: {error}")
        return RedirectResponse(f"{frontend_url}/settings?error={error}")

    if not code:
        return RedirectResponse(f"{frontend_url}/settings?error=missing_code")

    # 1. Verify state in DB
    result = await db.execute(select(OAuthState).where(OAuthState.state == state))
    oauth_state = result.scalar_one_or_none()

    if not oauth_state:
        logger.warning("Gmail OAuth state not found in DB or already consumed")
        return RedirectResponse(f"{frontend_url}/settings?error=state_expired")

    if oauth_state.expires_at < datetime.now(timezone.utc):
        await db.delete(oauth_state)
        await db.commit()
        return RedirectResponse(f"{frontend_url}/settings?error=state_expired")

    # Unpack workspace_id, user_id, and raw_nonce
    try:
        ws_str, uid_str, expected_nonce = oauth_state.browser_nonce.split(":", 2)
        workspace_id = uuid.UUID(ws_str)
        user_id = uuid.UUID(uid_str)
    except Exception as e:
        logger.error(f"Failed to unpack OAuth state context: {e}")
        await db.delete(oauth_state)
        await db.commit()
        return RedirectResponse(f"{frontend_url}/settings?error=invalid_state_context")

    # Verify cookie nonce if available
    cookie_nonce = request.cookies.get("st_gmail_oauth_nonce")
    if cookie_nonce and cookie_nonce != expected_nonce:
        logger.warning("Gmail OAuth nonce mismatch")
        await db.delete(oauth_state)
        await db.commit()
        return RedirectResponse(f"{frontend_url}/settings?error=nonce_mismatch")

    # Consume state
    await db.delete(oauth_state)
    await db.commit()

    try:
        # 3. Exchange code for credentials using PKCE code_verifier if present
        code_verifier = request.cookies.get("st_gmail_code_verifier")
        gmail_redirect_uri = _get_gmail_redirect_uri(request)
        creds_data = await gmail_service.exchange_code(
            code,
            code_verifier=code_verifier,
            redirect_uri=gmail_redirect_uri,
        )

        # 4. Get email address
        import googleapiclient.discovery
        import google.oauth2.credentials
        import asyncio

        email_address = "unknown"
        try:
            temp_creds = google.oauth2.credentials.Credentials(
                token=creds_data["token"],
                client_id=settings.GOOGLE_CLIENT_ID,
                client_secret=settings.GOOGLE_CLIENT_SECRET,
            )
            def _get_profile():
                service = googleapiclient.discovery.build('gmail', 'v1', credentials=temp_creds)
                return service.users().getProfile(userId='me').execute()

            profile = await asyncio.to_thread(_get_profile)
            email_address = profile.get("emailAddress", "unknown")
        except Exception as profile_err:
            logger.warning(f"Could not fetch Gmail profile: {profile_err}")
            # Fallback to user email
            user_obj = await db.get(User, user_id)
            if user_obj:
                email_address = user_obj.email

        # 5. Create or update connection
        result = await db.execute(
            select(GmailConnection).where(
                GmailConnection.workspace_id == workspace_id,
            )
        )
        connection = result.scalar_one_or_none()

        encrypted_access = encrypt_token(creds_data["token"])
        encrypted_refresh = encrypt_token(creds_data.get("refresh_token", ""))

        if connection:
            connection.email_address = email_address
            connection.encrypted_access_token = encrypted_access
            if creds_data.get("refresh_token"):
                connection.encrypted_refresh_token = encrypted_refresh
            connection.token_expires_at = creds_data.get("expiry")
            connection.status = "ACTIVE"
            connection.user_id = user_id
            connection.scopes = creds_data.get("scopes", [])
            connection.error_message = None
            connection.last_sync_cursor = None  # Reset pagination cursor so sync starts fresh
        else:
            connection = GmailConnection(
                workspace_id=workspace_id,
                user_id=user_id,
                email_address=email_address,
                provider="google",
                encrypted_access_token=encrypted_access,
                encrypted_refresh_token=encrypted_refresh,
                token_expires_at=creds_data.get("expiry"),
                scopes=creds_data.get("scopes", []),
                status="ACTIVE",
                last_sync_cursor=None,
            )
            db.add(connection)

        await db.commit()
        await db.refresh(connection)

        # Automatically enqueue initial Gmail sync in the background
        try:
            from app.worker import sync_gmail_account, _async_sync_gmail_account
            import asyncio
            job_id = str(uuid.uuid4())
            job = GmailSyncJob(
                job_id=job_id,
                workspace_id=workspace_id,
                gmail_connection_id=connection.id,
                status="QUEUED"
            )
            db.add(job)
            await db.commit()
            try:
                sync_gmail_account.delay(job_id, str(workspace_id), str(connection.id))
            except Exception:
                asyncio.create_task(_async_sync_gmail_account(None, job_id, str(workspace_id), str(connection.id)))
            logger.info(f"Auto-triggered initial Gmail sync job {job_id} for workspace {workspace_id}")
        except Exception as sync_err:
            logger.warning(f"Could not auto-trigger initial Gmail sync: {sync_err}")

        response = RedirectResponse(f"{frontend_url}/settings?status=connected")
        response.delete_cookie("st_gmail_oauth_nonce", path="/")
        response.delete_cookie("st_gmail_code_verifier", path="/")
        return response

    except Exception as e:
        import urllib.parse
        logger.error(f"Gmail OAuth callback failed: {e}")
        err_msg = urllib.parse.quote(str(e))
        response = RedirectResponse(f"{frontend_url}/settings?error={err_msg}")
        response.delete_cookie("st_gmail_oauth_nonce", path="/")
        response.delete_cookie("st_gmail_code_verifier", path="/")
        return response


# ── Gmail Integration Management ──────────────────────────────────────────────

from pydantic import BaseModel, Field
from app.models.email_analysis import EmailAnalysis, AnalysisStatus
from sqlalchemy import func

class GmailConfigUpdate(BaseModel):
    monitoring_enabled: bool | None = None
    analysis_mode: str | None = Field(None, pattern="^(AUTO|MANUAL)$")


@router.get("/workspaces/{workspace_id}/integrations/gmail")
async def get_gmail_connection(
    workspace_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    member=Depends(require_workspace_role("owner", "admin", "editor", "viewer")),
):
    """Get Gmail connection status and configuration for the workspace."""
    result = await db.execute(select(GmailConnection).where(GmailConnection.workspace_id == workspace_id))
    connection = result.scalar_one_or_none()
    
    if not connection:
        return {"status": "NOT_CONNECTED"}

    # Count fetched and analyzed emails for this workspace
    fetched_count = await db.scalar(
        select(func.count(EmailAnalysis.id)).where(
            EmailAnalysis.workspace_id == workspace_id,
            EmailAnalysis.source_provider.in_(["google", "gmail"]),
        )
    ) or 0

    analyzed_count = await db.scalar(
        select(func.count(EmailAnalysis.id)).where(
            EmailAnalysis.workspace_id == workspace_id,
            EmailAnalysis.source_provider.in_(["google", "gmail"]),
            EmailAnalysis.status == AnalysisStatus.COMPLETE,
        )
    ) or 0
        
    return {
        "id": connection.id,
        "email_address": connection.email_address,
        "status": connection.status,
        "monitoring_enabled": connection.monitoring_enabled if hasattr(connection, "monitoring_enabled") else True,
        "analysis_mode": connection.analysis_mode if hasattr(connection, "analysis_mode") else "AUTO",
        "last_sync_at": connection.last_sync_at,
        "error_message": connection.error_message,
        "emails_fetched": fetched_count,
        "emails_analyzed": analyzed_count,
        "workspace_id": connection.workspace_id,
    }


@router.patch("/workspaces/{workspace_id}/integrations/gmail/config")
async def update_gmail_config(
    workspace_id: uuid.UUID,
    config: GmailConfigUpdate,
    db: AsyncSession = Depends(get_db),
    member=Depends(require_workspace_role("owner", "admin", "editor")),
):
    """Update Gmail integration monitoring status and analysis mode."""
    result = await db.execute(select(GmailConnection).where(GmailConnection.workspace_id == workspace_id))
    connection = result.scalar_one_or_none()
    
    if not connection:
        raise HTTPException(status_code=404, detail="Gmail connection not found")

    if config.monitoring_enabled is not None:
        connection.monitoring_enabled = config.monitoring_enabled
    if config.analysis_mode is not None:
        connection.analysis_mode = config.analysis_mode.upper()

    await db.commit()
    await db.refresh(connection)

    # Count fetched and analyzed emails
    fetched_count = await db.scalar(
        select(func.count(EmailAnalysis.id)).where(
            EmailAnalysis.workspace_id == workspace_id,
            EmailAnalysis.source_provider.in_(["google", "gmail"]),
        )
    ) or 0

    analyzed_count = await db.scalar(
        select(func.count(EmailAnalysis.id)).where(
            EmailAnalysis.workspace_id == workspace_id,
            EmailAnalysis.source_provider.in_(["google", "gmail"]),
            EmailAnalysis.status == AnalysisStatus.COMPLETE,
        )
    ) or 0

    return {
        "id": connection.id,
        "email_address": connection.email_address,
        "status": connection.status,
        "monitoring_enabled": connection.monitoring_enabled,
        "analysis_mode": connection.analysis_mode,
        "last_sync_at": connection.last_sync_at,
        "error_message": connection.error_message,
        "emails_fetched": fetched_count,
        "emails_analyzed": analyzed_count,
        "workspace_id": connection.workspace_id,
    }


@router.post("/workspaces/{workspace_id}/integrations/gmail/sync")
async def sync_gmail(
    workspace_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    member=Depends(require_workspace_role("owner", "admin", "editor")),
):
    """Trigger background synchronization for Gmail."""
    result = await db.execute(select(GmailConnection).where(GmailConnection.workspace_id == workspace_id))
    connection = result.scalar_one_or_none()
    
    if not connection or connection.status != "ACTIVE":
        raise HTTPException(status_code=400, detail="Active Gmail connection not found")
        
    from app.worker import sync_gmail_account, _async_sync_gmail_account
    import asyncio
    
    job_id = str(uuid.uuid4())
    job = GmailSyncJob(
        job_id=job_id,
        workspace_id=workspace_id,
        gmail_connection_id=connection.id,
        status="QUEUED"
    )
    db.add(job)
    await db.commit()
    
    try:
        sync_gmail_account.delay(job_id, str(workspace_id), str(connection.id))
    except Exception:
        asyncio.create_task(_async_sync_gmail_account(None, job_id, str(workspace_id), str(connection.id)))
    
    return {"status": "QUEUED", "job_id": job_id}


@router.post("/workspaces/{workspace_id}/integrations/gmail/disconnect")
async def disconnect_gmail(
    workspace_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    member=Depends(require_workspace_role("owner", "admin", "editor")),
):
    """Revoke and remove Gmail connection."""
    result = await db.execute(select(GmailConnection).where(GmailConnection.workspace_id == workspace_id))
    connection = result.scalar_one_or_none()
    
    if not connection:
        raise HTTPException(status_code=404, detail="Gmail connection not found")
        
    await gmail_service.revoke_connection(db, connection)
    await db.delete(connection)
    await db.commit()
    return {"status": "DISCONNECTED"}


@router.get("/workspaces/{workspace_id}/integrations/gmail/messages")
async def list_gmail_messages_direct(
    workspace_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    member=Depends(require_workspace_role("owner", "admin", "editor")),
):
    """Directly list messages from Gmail API (Proxy)."""
    result = await db.execute(select(GmailConnection).where(GmailConnection.workspace_id == workspace_id))
    connection = result.scalar_one_or_none()
    
    if not connection or connection.status != "ACTIVE":
        raise HTTPException(status_code=400, detail="Active Gmail connection not found")
        
    messages = await gmail_service.list_messages(db, connection, max_results=10)
    return messages
