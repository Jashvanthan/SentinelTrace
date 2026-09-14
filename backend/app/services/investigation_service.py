"""
SentinelTrace Backend — Analyst Investigation Workspace Service
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.logging import get_logger
from app.models.campaign import Campaign
from app.models.email_analysis import EmailAnalysis
from app.models.investigation import (
    AnalystFinding,
    AnalystNote,
    EvidenceVerification,
    FindingSeverity,
    Investigation,
    InvestigationEntity,
    InvestigationStatus,
    VerificationStatus,
)
from app.models.ioc import IOC
from app.services.audit_service import write_audit_log
from app.services.forensic_timeline_service import ForensicTimelineService

logger = get_logger("sentineltrace.investigation_service")


class InvestigationService:
    """Master orchestrator for analyst investigation cases, evidence references, notes, findings, and verifications."""

    @staticmethod
    async def compute_risk_summary(
        db: AsyncSession,
        investigation: Investigation,
    ) -> dict[str, Any]:
        """
        Compute an explainable 0–100 Investigation Risk Score based on attached entities and analyst findings.
        """
        total_score = 0.0
        contributors: list[dict[str, Any]] = []
        high_risk_entities: list[str] = []

        # 1. Findings Contributions
        for f in investigation.findings:
            pts = 0.0
            if f.severity == FindingSeverity.CRITICAL:
                pts = 35.0
            elif f.severity == FindingSeverity.HIGH:
                pts = 25.0
            elif f.severity == FindingSeverity.MEDIUM:
                pts = 15.0
            elif f.severity == FindingSeverity.LOW:
                pts = 5.0

            if pts > 0:
                total_score += pts
                contributors.append({
                    "source": "Analyst Finding",
                    "title": f.title,
                    "points": pts,
                    "severity": f.severity.value,
                })

        # 2. Attached Entities Contributions (Email threat scores & IOC scores)
        for entity in investigation.entities:
            if entity.entity_type == "EMAIL":
                try:
                    email_uuid = uuid.UUID(entity.entity_id)
                    email = await db.get(EmailAnalysis, email_uuid)
                    if email and email.risk_score:
                        pts = (email.risk_score / 100.0) * 20.0
                        total_score += pts
                        contributors.append({
                            "source": "Attached Email",
                            "title": email.subject or str(email.id)[:8],
                            "points": round(pts, 1),
                            "severity": email.threat_category or "MEDIUM",
                        })
                        if email.risk_score >= 70:
                            high_risk_entities.append(f"Email: {email.subject or str(email.id)[:8]}")
                except Exception:
                    pass
            elif entity.entity_type in ["IOC", "IP", "DOMAIN", "URL", "HASH"]:
                try:
                    ioc_uuid = uuid.UUID(entity.entity_id)
                    ioc = await db.get(IOC, ioc_uuid)
                    if ioc and ioc.threat_score:
                        pts = (ioc.threat_score / 100.0) * 15.0
                        total_score += pts
                        contributors.append({
                            "source": f"Attached {entity.entity_type}",
                            "title": ioc.value[:30],
                            "points": round(pts, 1),
                            "severity": "HIGH" if ioc.is_malicious else "LOW",
                        })
                        if ioc.is_malicious or (ioc.threat_score or 0) >= 70:
                            high_risk_entities.append(f"{entity.entity_type}: {ioc.value[:30]}")
                except Exception:
                    pass

        final_score = min(100, int(round(total_score)))
        
        severity = "CLEAN"
        if final_score >= 80:
            severity = "CRITICAL"
        elif final_score >= 60:
            severity = "HIGH"
        elif final_score >= 40:
            severity = "MODERATE"
        elif final_score >= 20:
            severity = "LOW"

        return {
            "risk_score": final_score,
            "severity": severity,
            "evidence_count": len(investigation.verifications),
            "entity_count": len(investigation.entities),
            "finding_count": len(investigation.findings),
            "high_risk_entities": high_risk_entities,
            "contributors": contributors,
        }

    @classmethod
    async def create_investigation(
        cls,
        db: AsyncSession,
        workspace_id: uuid.UUID,
        user_id: uuid.UUID,
        name: str,
        description: str | None = None,
        starting_entity_type: str | None = None,
        starting_entity_id: str | None = None,
        starting_entity_value: str | None = None,
    ) -> Investigation:
        investigation = Investigation(
            id=uuid.uuid4(),
            workspace_id=workspace_id,
            name=name,
            description=description,
            status=InvestigationStatus.OPEN,
            created_by_id=user_id,
            risk_score=0,
        )
        db.add(investigation)
        await db.flush()

        if starting_entity_type and starting_entity_id:
            entity = InvestigationEntity(
                id=uuid.uuid4(),
                workspace_id=workspace_id,
                investigation_id=investigation.id,
                entity_type=starting_entity_type.upper(),
                entity_id=starting_entity_id,
                entity_value=starting_entity_value,
                added_by_id=user_id,
            )
            db.add(entity)

        await write_audit_log(
            db=db,
            action="INVESTIGATION_CREATED",
            user_id=user_id,
            resource_type="investigation",
            resource_id=str(investigation.id),
            details={"name": name, "workspace_id": str(workspace_id)},
            outcome="SUCCESS",
        )
        await db.commit()
        return await cls.get_investigation(db, workspace_id, investigation.id)

    @classmethod
    async def get_investigation(
        cls,
        db: AsyncSession,
        workspace_id: uuid.UUID,
        investigation_id: uuid.UUID,
    ) -> Investigation | None:
        investigation = await db.scalar(
            select(Investigation)
            .options(
                selectinload(Investigation.entities),
                selectinload(Investigation.notes),
                selectinload(Investigation.findings),
                selectinload(Investigation.verifications),
            )
            .where(
                Investigation.id == investigation_id,
                Investigation.workspace_id == workspace_id,
            )
        )
        if investigation:
            summary = await cls.compute_risk_summary(db, investigation)
            investigation.risk_score = summary["risk_score"]
            setattr(investigation, "risk_summary", summary)
        return investigation

    @classmethod
    async def list_investigations(
        cls,
        db: AsyncSession,
        workspace_id: uuid.UUID,
        status: InvestigationStatus | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> tuple[list[Investigation], int]:
        query = select(Investigation).where(Investigation.workspace_id == workspace_id)
        if status:
            query = query.where(Investigation.status == status)

        total_stmt = select(func.count()).select_from(query.subquery())
        total = (await db.scalar(total_stmt)) or 0

        stmt = (
            query.options(
                selectinload(Investigation.entities),
                selectinload(Investigation.notes),
                selectinload(Investigation.findings),
                selectinload(Investigation.verifications),
            )
            .order_by(Investigation.updated_at.desc())
            .limit(limit)
            .offset(offset)
        )
        items = (await db.execute(stmt)).scalars().all()
        
        for inv in items:
            summary = await cls.compute_risk_summary(db, inv)
            inv.risk_score = summary["risk_score"]
            setattr(inv, "risk_summary", summary)

        return items, total

    @classmethod
    async def update_investigation_status(
        cls,
        db: AsyncSession,
        workspace_id: uuid.UUID,
        user_id: uuid.UUID,
        investigation_id: uuid.UUID,
        new_status: InvestigationStatus,
    ) -> Investigation | None:
        investigation = await cls.get_investigation(db, workspace_id, investigation_id)
        if not investigation:
            return None

        old_status = investigation.status
        investigation.status = new_status

        await write_audit_log(
            db=db,
            action="INVESTIGATION_STATUS_CHANGED",
            user_id=user_id,
            resource_type="investigation",
            resource_id=str(investigation.id),
            details={"from": old_status.value, "to": new_status.value, "workspace_id": str(workspace_id)},
            outcome="SUCCESS",
        )
        await db.commit()
        return await cls.get_investigation(db, workspace_id, investigation_id)
