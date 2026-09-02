"""
SentinelTrace Backend — Shared Audit Logging Service
"""
import uuid
from typing import Any, Dict, Optional

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog


async def write_audit_log(
    db: AsyncSession,
    action: str,
    user_id: Optional[uuid.UUID] = None,
    request: Optional[Request] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    outcome: str = "SUCCESS",
    error_message: Optional[str] = None,
) -> None:
    """
    Writes a secure, immutable audit log entry.
    """
    # Exclude sensitive data from details if passed accidentally
    safe_details = {}
    if details:
        sensitive_keys = {"password", "token", "secret", "key", "jwt", "body", "email_body", "credentials"}
        for k, v in details.items():
            if not any(sk in k.lower() for sk in sensitive_keys):
                safe_details[k] = v
            else:
                safe_details[k] = "[REDACTED]"

    log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=request.client.host if request and request.client else None,
        user_agent=request.headers.get("User-Agent") if request else None,
        details=safe_details if safe_details else None,
        outcome=outcome,
        error_message=error_message,
    )
    db.add(log)
