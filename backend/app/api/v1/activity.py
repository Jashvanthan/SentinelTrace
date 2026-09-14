"""
SentinelTrace Backend — Activity & Audit Log API
"""
from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import selectinload

from app.core.deps import CurrentUser, DbSession
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.activity import (
    ActivityLogItem,
    ActivityLogListResponse,
    ActivityLogSummary,
)

router = APIRouter(prefix="/activity", tags=["Activity & Audit Logs"])


@router.get("/", response_model=ActivityLogListResponse)
async def list_activity_logs(
    db: DbSession,
    current_user: CurrentUser,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    action: str | None = Query(None, description="Filter by action name"),
    outcome: str | None = Query(None, description="Filter by outcome (SUCCESS, FAILURE, DENIED)"),
    search: str | None = Query(None, max_length=128, description="Free text search"),
):
    """
    List security audit and activity logs with actor details and summary metrics.
    """
    base_query = select(
        AuditLog,
        User.email.label("user_email"),
        User.full_name.label("user_name"),
    ).outerjoin(User, AuditLog.user_id == User.id)

    filters = []

    if action and action.strip() and action.strip().upper() != "ALL":
        filters.append(AuditLog.action.ilike(f"%{action.strip()}%"))

    if outcome and outcome.strip() and outcome.strip().upper() != "ALL":
        filters.append(AuditLog.outcome.ilike(f"%{outcome.strip()}%"))

    if search and search.strip():
        term = f"%{search.strip()}%"
        filters.append(
            or_(
                AuditLog.action.ilike(term),
                AuditLog.resource_type.ilike(term),
                AuditLog.resource_id.ilike(term),
                AuditLog.ip_address.ilike(term),
                AuditLog.error_message.ilike(term),
                User.email.ilike(term),
                User.full_name.ilike(term),
            )
        )

    if filters:
        base_query = base_query.where(*filters)

    # Count total matching query
    count_query = select(func.count(AuditLog.id)).outerjoin(User, AuditLog.user_id == User.id)
    if filters:
        count_query = count_query.where(*filters)
    total = await db.scalar(count_query) or 0

    # Execute paginated query
    stmt = (
        base_query
        .order_by(AuditLog.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await db.execute(stmt)
    rows = result.all()

    items: list[ActivityLogItem] = []
    for log, user_email, user_name in rows:
        items.append(
            ActivityLogItem(
                id=log.id,
                action=log.action,
                resource_type=log.resource_type,
                resource_id=log.resource_id,
                user_id=log.user_id,
                user_email=user_email,
                user_name=user_name,
                ip_address=log.ip_address,
                user_agent=log.user_agent,
                outcome=log.outcome,
                details=log.details,
                error_message=log.error_message,
                created_at=log.created_at,
            )
        )

    # Compute overall summary metrics
    total_events = await db.scalar(select(func.count(AuditLog.id))) or 0
    success_count = await db.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.outcome == "SUCCESS")
    ) or 0
    failure_count = await db.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.outcome.in_(["FAILURE", "FAILED", "DENIED", "ERROR"]))
    ) or 0
    unique_users = await db.scalar(
        select(func.count(func.distinct(AuditLog.user_id))).where(AuditLog.user_id.is_not(None))
    ) or 0

    # Top 5 actions
    top_actions_stmt = (
        select(AuditLog.action, func.count(AuditLog.id).label("cnt"))
        .group_by(AuditLog.action)
        .order_by(desc("cnt"))
        .limit(5)
    )
    top_actions_res = await db.execute(top_actions_stmt)
    top_actions = {act: cnt for act, cnt in top_actions_res.all()}

    summary = ActivityLogSummary(
        total_events=total_events,
        success_count=success_count,
        failure_count=failure_count,
        unique_users_count=unique_users,
        top_actions=top_actions,
    )

    return ActivityLogListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        summary=summary,
    )
