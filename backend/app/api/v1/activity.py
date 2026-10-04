"""
SentinelTrace Backend — Activity & Audit Log API
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import ColumnElement, String, cast, desc, func, or_, select

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
    start_date: datetime | None = Query(None, description="Filter events from timestamp"),
    end_date: datetime | None = Query(None, description="Filter events until timestamp"),
)-> ActivityLogListResponse:
    """
    List security audit and activity logs with actor details and summary metrics.
    """
    base_query = select(
        AuditLog,
        User.email.label("user_email"),
        User.full_name.label("user_name"),
    ).outerjoin(User, AuditLog.user_id == User.id)

    # Explicitly typed to ColumnElement[bool] to allow BinaryExpression, or_(), etc.
    filters: list[ColumnElement[bool]] = []

    if action and action.strip() and action.strip().upper() != "ALL":
        filters.append(AuditLog.action.ilike(f"%{action.strip()}%"))

    if outcome and outcome.strip() and outcome.strip().upper() != "ALL":
        filters.append(AuditLog.outcome.ilike(f"%{outcome.strip()}%"))

    if start_date:
        filters.append(AuditLog.created_at >= start_date)

    if end_date:
        filters.append(AuditLog.created_at <= end_date)

    if search and search.strip():
        term = f"%{search.strip()}%"
        filters.append(
            or_(
                AuditLog.action.ilike(term),
                AuditLog.resource_type.ilike(term),
                # Cast to String to safely handle UUID/Integer columns in PostgreSQL
                cast(AuditLog.resource_id, String).ilike(term),
                cast(AuditLog.ip_address, String).ilike(term),
                AuditLog.error_message.ilike(term),
                User.email.ilike(term),
                User.full_name.ilike(term),
            )
        )

    if filters:
        base_query = base_query.where(*filters)

    # 1. Count total matching query
    count_query = select(func.count(AuditLog.id))
    if search and search.strip():
        count_query = count_query.outerjoin(User, AuditLog.user_id == User.id)
    if filters:
        count_query = count_query.where(*filters)
    total = await db.scalar(count_query) or 0

    # 2. Execute paginated query
    stmt = (
        base_query
        .order_by(AuditLog.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await db.execute(stmt)
    rows = result.all()

    items = [
        ActivityLogItem(
            id=log.id,
            action=log.action,
            resource_type=log.resource_type,
            resource_id=str(log.resource_id) if log.resource_id is not None else None,
            user_id=log.user_id,
            user_email=user_email,
            user_name=user_name,
            ip_address=str(log.ip_address) if log.ip_address is not None else None,
            user_agent=log.user_agent,
            outcome=log.outcome,
            details=log.details,
            error_message=log.error_message,
            created_at=log.created_at,
        )
        for log, user_email, user_name in rows
    ]

    # 3. Optimized summary query (1 query instead of 4 separate table scans)
    summary_stmt = select(
        func.count(AuditLog.id).label("total_events"),
        func.count(AuditLog.id).filter(AuditLog.outcome == "SUCCESS").label("success_count"),
        func.count(AuditLog.id).filter(
            AuditLog.outcome.in_(["FAILURE", "FAILED", "DENIED", "ERROR"])
        ).label("failure_count"),
        func.count(func.distinct(AuditLog.user_id)).filter(
            AuditLog.user_id.is_not(None)
        ).label("unique_users"),
    )
    summary_res = (await db.execute(summary_stmt)).one()

    # 4. Top 5 actions
    top_actions_stmt = (
        select(AuditLog.action, func.count(AuditLog.id).label("cnt"))
        .group_by(AuditLog.action)
        .order_by(desc("cnt"))
        .limit(5)
    )
    top_actions_res = await db.execute(top_actions_stmt)
    top_actions = {act: cnt for act, cnt in top_actions_res.all()}

    summary = ActivityLogSummary(
        total_events=summary_res.total_events or 0,
        success_count=summary_res.success_count or 0,
        failure_count=summary_res.failure_count or 0,
        unique_users_count=summary_res.unique_users or 0,
        top_actions=top_actions,
    )

    return ActivityLogListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        summary=summary,
    )
