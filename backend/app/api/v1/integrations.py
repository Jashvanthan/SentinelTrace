"""
SentinelTrace Backend — Integrations API
"""
from __future__ import annotations

import logging
import uuid
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import secrets

from app.core.deps import get_current_user, require_workspace_role
from app.db.session import get_db_session as get_db
from app.core.config import get_settings
from app.models.integrations import GmailConnection
from app.models.jobs import GmailSyncJob
from app.models.oauth import OAuthState
from app.models.user import User
from app.services.encryption_service import encrypt_token
from app.services.gmail_service import gmail_service

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Gmail OAuth Connect Flow ──────────────────────────────────────────────────

@router.get("/workspaces/{workspace_id}/integrations/gmail/connect")
async def connect_gmail(
    workspace_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    # Must be at least EDITOR to connect integrations
    member=Depends(require_workspace_role("owner", "admin", "editor")),
    user: User = Depends(get_current_user),
):
    """
    Initiate Gmail OAuth connection for a specific workspace.
    """
    state_token = secrets.token_urlsafe(32)
    
    # Generate CSRF bound to this specific workspace and user
    oauth_state = OAuthState(
        state=state_token,
        provider="gmail",
        user_id=user.id,
        context=json.dumps({"workspace_id": str(workspace_id)}),
        expires_at=datetime.now(timezone.utc),  # Expiration handled by DB model logic typically, or add timedelta here
    )
    db.add(oauth_state)
    await db.commit()

    auth_url = gmail_service.get_authorization_url(state=state_token)
    
    # Store state nonce in cookie for strict binding
    response = RedirectResponse(url=auth_url)
    response.set_cookie(
        "st_gmail_oauth_nonce",
        state_token,
        httponly=True,
        secure=get_settings().is_production,
        samesite="lax",
        max_age=600,  # 10 minutes
    )
    return response


@router.get("/integrations/gmail/callback")
async def gmail_callback(
    request: Request,
    state: str = Query(..., description="OAuth state parameter"),
    code: str = Query(..., description="OAuth authorization code"),
    db: AsyncSession = Depends(get_db),
):
    """
    Handle Google OAuth callback for Gmail.
    """
    settings = get_settings()
    cookie_state = request.cookies.get("st_gmail_oauth_nonce")
    
    if not cookie_state or cookie_state != state:
        logger.warning("Gmail OAuth state mismatch or missing cookie")
        return RedirectResponse(f"{settings.FRONTEND_URL}/error?message=Invalid_OAuth_State")

    # Verify state in DB
    result = await db.execute(select(OAuthState).where(OAuthState.state == state, OAuthState.provider == "gmail"))
    oauth_state = result.scalar_one_or_none()
    
    if not oauth_state:
        logger.warning("Gmail OAuth state not found in DB")
        return RedirectResponse(f"{settings.FRONTEND_URL}/error?message=State_Expired")
        
    context = json.loads(oauth_state.context)
    workspace_id = uuid.UUID(context["workspace_id"])
    user_id = oauth_state.user_id

    # Consume state
    await db.delete(oauth_state)
    await db.commit()

    try:
        # Exchange code for token
        creds_data = await gmail_service.exchange_code(code)
        
        # Get email address using token (Optional but good for sanity. For now we use a generic API call if needed, or get it from ID token if included. Google sends ID token if openid scope is present. If we only used gmail.readonly, we need to call userinfo or gmail profile.)
        import googleapiclient.discovery
        import google.oauth2.credentials
        import asyncio
        
        temp_creds = google.oauth2.credentials.Credentials(token=creds_data["token"])
        def _get_profile():
            service = googleapiclient.discovery.build('gmail', 'v1', credentials=temp_creds)
            return service.users().getProfile(userId='me').execute()
        
        profile = await asyncio.to_thread(_get_profile)
        email_address = profile.get("emailAddress", "unknown")

        # Create or update connection
        result = await db.execute(
            select(GmailConnection).where(
                GmailConnection.workspace_id == workspace_id,
                GmailConnection.email_address == email_address
            )
        )
        connection = result.scalar_one_or_none()
        
        encrypted_access = encrypt_token(creds_data["token"])
        encrypted_refresh = encrypt_token(creds_data.get("refresh_token", ""))

        if connection:
            connection.encrypted_access_token = encrypted_access
            if creds_data.get("refresh_token"):
                connection.encrypted_refresh_token = encrypted_refresh
            connection.token_expires_at = creds_data.get("expiry")
            connection.status = "ACTIVE"
            connection.user_id = user_id
            connection.scopes = creds_data.get("scopes", [])
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
            )
            db.add(connection)
            
        await db.commit()
        
        response = RedirectResponse(f"{settings.FRONTEND_URL}/workspaces/{workspace_id}/integrations")
        response.delete_cookie("st_gmail_oauth_nonce")
        return response
        
    except Exception as e:
        logger.error(f"Gmail OAuth callback failed: {e}")
        return RedirectResponse(f"{settings.FRONTEND_URL}/error?message=Gmail_Integration_Failed")


# ── Gmail Integration Management ──────────────────────────────────────────────

@router.get("/workspaces/{workspace_id}/integrations/gmail")
async def get_gmail_connection(
    workspace_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    member=Depends(require_workspace_role("owner", "admin", "editor", "viewer")),
):
    """Get Gmail connection status for the workspace."""
    result = await db.execute(select(GmailConnection).where(GmailConnection.workspace_id == workspace_id))
    connection = result.scalar_one_or_none()
    
    if not connection:
        return {"status": "NOT_CONNECTED"}
        
    return {
        "id": connection.id,
        "email_address": connection.email_address,
        "status": connection.status,
        "last_sync_at": connection.last_sync_at,
        "error_message": connection.error_message,
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
        
    from app.worker import sync_gmail_account
    
    job_id = str(uuid.uuid4())
    job = GmailSyncJob(
        job_id=job_id,
        workspace_id=workspace_id,
        gmail_connection_id=connection.id,
        status="QUEUED"
    )
    db.add(job)
    await db.commit()
    
    # Trigger Celery task
    sync_gmail_account.delay(job_id, str(workspace_id), str(connection.id))
    
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
