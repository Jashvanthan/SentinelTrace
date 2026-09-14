"""
SentinelTrace Backend — FastAPI Dependency Injection

Provides reusable dependencies for:
- Database sessions (async)
- Current authenticated user
- Role-based authorization guards
- Settings injection
"""
from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import Cookie, Depends, HTTPException, Query, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.security import decode_access_token
from app.db.session import get_db_session

# ── Re-export for convenience ─────────────────────────────────────────────────
SettingsDep = Annotated[Settings, Depends(get_settings)]
DbSession = Annotated[AsyncSession, Depends(get_db_session)]

# ── Token Bearer ──────────────────────────────────────────────────────────────
bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user_payload(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Security(bearer_scheme)
    ] = None,
) -> dict:
    """
    Extract and validate the JWT from the Authorization: Bearer header.

    Returns the decoded payload dict.
    Raises 401 if missing or invalid.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(credentials.credentials)
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    return payload


# ── Current User Object (lazy import to avoid circular imports) ───────────────

async def get_current_user(
    payload: Annotated[dict, Depends(get_current_user_payload)],
    db: DbSession,
) -> "User":  # type: ignore[name-defined]  # noqa: F821
    """
    Resolve the authenticated user from the JWT payload.
    Returns the ORM User object.
    """
    from app.models.user import User
    from app.services.user_service import get_user_by_id

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token: missing subject")

    user = await get_user_by_id(db, UUID(user_id))
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account is deactivated")

    return user


CurrentUser = Annotated["User", Depends(get_current_user)]  # type: ignore[name-defined]


# ── Role-Based Authorization ──────────────────────────────────────────────────

def require_role(*allowed_roles: str):
    """
    Dependency factory that enforces role-based access.

    Usage:
        @router.get("/admin-only")
        async def endpoint(user: Annotated[User, Depends(require_role("ADMIN"))]):
            ...
    """
    async def role_guard(user: CurrentUser) -> "User":  # type: ignore[name-defined]
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {list(allowed_roles)}",
            )
        return user
    return role_guard


AdminRequired = Annotated["User", Depends(require_role("ADMIN"))]
AnalystOrAbove = Annotated["User", Depends(require_role("ADMIN", "ANALYST"))]
AnyAuthenticatedUser = Annotated["User", Depends(get_current_user)]


def require_workspace_role(*allowed_roles: str):
    """
    Dependency factory to enforce workspace-level RBAC and prevent BOLA/IDOR.
    Returns the WorkspaceMember object if successful.
    Returns 404 if the user is not a member (prevents enumeration).
    Returns 403 if the user lacks the required role.
    """
    async def role_guard(
        request: Request,
        user: CurrentUser,
        db: DbSession,
    ):
        from sqlalchemy import select
        from app.models.workspace import WorkspaceMember

        raw_ws_id = request.path_params.get("workspace_id") or request.query_params.get("workspace_id")
        target_ws_id: UUID | None = None
        if raw_ws_id:
            try:
                target_ws_id = UUID(str(raw_ws_id))
            except (ValueError, TypeError):
                target_ws_id = None

        if not target_ws_id:
            target_ws_id = getattr(user, "active_workspace_id", None)

        if not target_ws_id:
            member = await db.scalar(
                select(WorkspaceMember).where(WorkspaceMember.user_id == user.id)
            )
            if not member:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "No workspace found for user")
        else:
            member = await db.scalar(
                select(WorkspaceMember).where(
                    WorkspaceMember.workspace_id == target_ws_id,
                    WorkspaceMember.user_id == user.id,
                )
            )
            if not member:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")
        
        if allowed_roles and member.role not in allowed_roles:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, 
                f"Insufficient workspace permissions. Required: {list(allowed_roles)}"
            )
            
        return member

    return role_guard


# ── Request Correlation ID ────────────────────────────────────────────────────

async def get_correlation_id(request: Request) -> str:
    """Extract or generate a correlation ID for distributed tracing."""
    return request.state.correlation_id if hasattr(request.state, "correlation_id") else ""
