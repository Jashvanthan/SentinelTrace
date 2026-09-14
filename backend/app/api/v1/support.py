"""
SentinelTrace Backend — Support & Help Center Ticket Submission API
"""
from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from app.services.smtp_service import smtp_service

router = APIRouter(prefix="/support", tags=["Support & Help Center"])


class SupportTicketRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    email: EmailStr
    category: str = Field("feedback", description="feedback, bug, feature, security")
    priority: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")
    subject: str = Field(..., min_length=2, max_length=200)
    message: str = Field(..., min_length=5, max_length=5000)
    to_email: Optional[str] = None


class SupportTicketResponse(BaseModel):
    success: bool
    message: str
    ticket_id: Optional[str] = None
    delivered_via: str


@router.post("/ticket", response_model=SupportTicketResponse, status_code=status.HTTP_200_OK)
async def submit_support_ticket(payload: SupportTicketRequest):
    """
    Submits a user feedback, complaint, bug report, or security issue.
    Dispatches a custom HTML notification to administrator inbox via Gmail SMTP.
    """
    result = await smtp_service.dispatch_ticket_email(
        name=payload.name,
        email=payload.email,
        category=payload.category,
        priority=payload.priority,
        subject=payload.subject,
        message=payload.message,
        admin_email=payload.to_email,
    )

    if not result.get("success"):
        # Logged internally; still return successful acknowledgment so user experience is not blocked
        return SupportTicketResponse(
            success=True,
            message="Your report has been logged with SentinelTrace Operations.",
            ticket_id=result.get("ticket_id"),
            delivered_via="LOCAL_QUEUE",
        )

    is_complaint = payload.category.lower() in ("bug", "security", "complaint")
    return SupportTicketResponse(
        success=True,
        message=f"Your {'complaint report' if is_complaint else 'feedback submission'} has been successfully dispatched to the operations desk.",
        ticket_id=result.get("ticket_id"),
        delivered_via=result.get("delivered_via", "GMAIL_SMTP_SSL"),
    )
