"""
SentinelTrace Backend — Forensic Investigation Timeline Service
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.logging import get_logger
from app.models.campaign import Campaign, CampaignMember
from app.models.email_analysis import EmailAnalysis
from app.models.ioc import IOC

logger = get_logger("sentineltrace.forensic_timeline")


class ForensicTimelineService:
    """Constructs a chronological UTC investigation timeline for emails and campaigns."""

    @staticmethod
    async def build_campaign_timeline(
        db: AsyncSession,
        workspace_id: uuid.UUID,
        campaign_id: uuid.UUID,
    ) -> list[dict[str, Any]]:
        """
        Build an ordered timeline of events for a specific campaign within a workspace.
        """
        campaign = await db.scalar(
            select(Campaign)
            .options(selectinload(Campaign.members).selectinload(CampaignMember.email_analysis))
            .where(
                Campaign.id == campaign_id,
                Campaign.workspace_id == workspace_id,
            )
        )
        if not campaign:
            return []

        events: list[dict[str, Any]] = []

        # 1. Campaign Created Event
        if campaign.created_at:
            events.append({
                "id": f"campaign-created-{campaign.id}",
                "timestamp": campaign.created_at.isoformat(),
                "event_type": "CAMPAIGN_CORRELATION_CREATED",
                "title": f"Campaign '{campaign.name}' Formed",
                "description": f"Automated correlation established campaign (Score: {campaign.correlation_score or 0})",
                "source": "SentinelTrace Correlation Engine",
                "entity_type": "CAMPAIGN",
                "entity_id": str(campaign.id),
                "confidence": "HIGH" if (campaign.confidence or 0) >= 0.7 else "MEDIUM",
            })

        # 2. Member Email Events & Header Hops
        for member in campaign.members:
            email = member.email_analysis
            if not email:
                continue

            email_ts = email.received_date or (email.created_at.isoformat() if email.created_at else datetime.now(UTC).isoformat())
            events.append({
                "id": f"email-received-{email.id}",
                "timestamp": email_ts,
                "event_type": "EMAIL_RECEIVED",
                "title": f"Email Received: {email.subject or 'No Subject'}",
                "description": f"Sender: {email.sender or 'Unknown'} | Threat Category: {email.threat_category or 'BENIGN'}",
                "source": "Email Analysis Pipeline",
                "entity_type": "EMAIL",
                "entity_id": str(email.id),
                "confidence": "HIGH",
            })

            # Fetch IOCs for email
            iocs = await db.scalars(
                select(IOC).where(
                    IOC.analysis_id == email.id,
                    IOC.workspace_id == workspace_id,
                )
            )
            for ioc in iocs:
                ioc_ts = ioc.first_seen_at or email_ts
                events.append({
                    "id": f"ioc-observed-{ioc.id}",
                    "timestamp": ioc_ts,
                    "event_type": f"{ioc.ioc_type.value if hasattr(ioc.ioc_type, 'value') else ioc.ioc_type}_OBSERVED",
                    "title": f"Observed {ioc.ioc_type.value if hasattr(ioc.ioc_type, 'value') else ioc.ioc_type}: {ioc.value[:40]}",
                    "description": f"Threat Score: {ioc.threat_score or 0} | Malicious: {bool(ioc.is_malicious)}",
                    "source": ioc.source or "IOC Extraction",
                    "entity_type": "IOC",
                    "entity_id": str(ioc.id),
                    "confidence": "HIGH" if (ioc.confidence_score or 0) >= 0.7 else "MEDIUM",
                })

        # Sort timeline strictly by UTC timestamp ascending
        events.sort(key=lambda x: x["timestamp"])
        return events
