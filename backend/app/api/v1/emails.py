"""
SentinelTrace Backend — Email Analysis API Router

Endpoints:
  POST /emails/upload              Upload .eml file → trigger analysis
  GET  /emails/                    List analyses (paginated, filterable)
  GET  /emails/{id}                Get full analysis detail
  GET  /emails/{id}/report         Get signed GCS URL for evidence report
  DELETE /emails/{id}              Delete an analysis
  GET  /emails/{id}/status         SSE stream for real-time status updates
"""
from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select

from app.core.deps import AnalystOrAbove, CurrentUser, DbSession
from app.core.logging import get_logger
from app.models.email_analysis import AnalysisStatus, EmailAnalysis, SeverityLevel, ThreatCategory
from app.schemas.email_analysis import (
    AnalysisTriggerResponse,
    EmailAnalysisDetail,
    EmailAnalysisListResponse,
    EmailAnalysisSummary,
)
from app.services.threat_service import ThreatAnalysisPipeline

router = APIRouter(prefix="/emails", tags=["Email Analysis"])
logger = get_logger("sentineltrace.api.emails")

MAX_EML_SIZE = 50 * 1024 * 1024  # 50 MB


@router.post("/upload", response_model=AnalysisTriggerResponse, status_code=status.HTTP_202_ACCEPTED)
async def upload_email(
    background_tasks: BackgroundTasks,
    db: DbSession,
    current_user: CurrentUser,
    file: UploadFile = File(..., description="Raw .eml file"),
    notes: str | None = Form(None),
    priority: str = Form("NORMAL"),
):
    """
    Upload a raw .eml file and trigger asynchronous threat analysis.

    The file is parsed, stored (encrypted) in GCS, and enriched against
    threat intelligence providers. Results are written back to the database.
    """
    # Validate file
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Only .eml files are accepted")

    raw_bytes = await file.read()
    if len(raw_bytes) == 0:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty file")
    if len(raw_bytes) > MAX_EML_SIZE:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File exceeds 50 MB limit")

    # Create analysis record
    analysis = EmailAnalysis(
        analyst_id=current_user.id,
        status=AnalysisStatus.PENDING,
        raw_eml_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        raw_eml_size_bytes=len(raw_bytes),
    )
    db.add(analysis)
    await db.flush()
    analysis_id = analysis.id

    logger.info("email_uploaded", analysis_id=str(analysis_id), size=len(raw_bytes))

    # Trigger background analysis
    background_tasks.add_task(_run_analysis, analysis_id, raw_bytes)

    return AnalysisTriggerResponse(
        analysis_id=analysis_id,
        status=AnalysisStatus.PENDING,
        message="Email received. Analysis started in background.",
    )


@router.get("/", response_model=EmailAnalysisListResponse)
async def list_analyses(
    db: DbSession,
    current_user: CurrentUser,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    status_filter: AnalysisStatus | None = Query(None, alias="status"),
    severity_filter: SeverityLevel | None = Query(None, alias="severity"),
    threat_category: ThreatCategory | None = Query(None),
    search: str | None = Query(None, max_length=256),
):
    """List email analyses with pagination and filtering."""
    q = select(EmailAnalysis)

    if status_filter:
        q = q.where(EmailAnalysis.status == status_filter)
    if severity_filter:
        q = q.where(EmailAnalysis.severity == severity_filter)
    if threat_category:
        q = q.where(EmailAnalysis.threat_category == threat_category)
    if search:
        q = q.where(
            EmailAnalysis.subject.ilike(f"%{search}%") |
            EmailAnalysis.sender_email.ilike(f"%{search}%") |
            EmailAnalysis.sender_domain.ilike(f"%{search}%")
        )

    total = await db.scalar(select(func.count()).select_from(q.subquery()))
    offset = (page - 1) * page_size
    result = await db.execute(
        q.order_by(EmailAnalysis.created_at.desc()).offset(offset).limit(page_size)
    )
    items = list(result.scalars())

    return EmailAnalysisListResponse(
        items=[EmailAnalysisSummary.model_validate(i) for i in items],
        total=total or 0,
        page=page,
        page_size=page_size,
    )


@router.get("/{analysis_id}", response_model=EmailAnalysisDetail)
async def get_analysis(analysis_id: uuid.UUID, db: DbSession, current_user: CurrentUser):
    """Get full analysis detail including IOCs, attachments, and AI summary."""
    analysis = await _get_or_404(db, analysis_id)
    return EmailAnalysisDetail.model_validate(analysis)


@router.delete("/{analysis_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_analysis(analysis_id: uuid.UUID, db: DbSession, _: AnalystOrAbove):
    """Delete an analysis and all associated data."""
    analysis = await _get_or_404(db, analysis_id)
    await db.delete(analysis)
    logger.info("analysis_deleted", analysis_id=str(analysis_id))


@router.get("/{analysis_id}/status")
async def stream_analysis_status(analysis_id: uuid.UUID, db: DbSession, current_user: CurrentUser):
    """
    Server-Sent Events stream for real-time analysis status updates.
    Closes automatically when analysis reaches COMPLETE or FAILED.
    """
    async def event_generator():
        for _ in range(60):  # Max 5 minutes of polling
            analysis = await db.get(EmailAnalysis, analysis_id)
            if analysis is None:
                yield f"data: {{\"error\": \"not_found\"}}\n\n"
                break

            payload = {
                "status": analysis.status.value,
                "severity": analysis.severity.value if analysis.severity else None,
                "threat_category": analysis.threat_category.value if analysis.threat_category else None,
                "threat_score": analysis.threat_score,
                "completed_at": analysis.completed_at.isoformat() if analysis.completed_at else None,
            }
            import json
            yield f"data: {json.dumps(payload)}\n\n"

            if analysis.status in (AnalysisStatus.COMPLETE, AnalysisStatus.FAILED):
                break

            await asyncio.sleep(5)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_or_404(db: DbSession, analysis_id: uuid.UUID) -> EmailAnalysis:
    from sqlalchemy.orm import selectinload
    result = await db.execute(
        select(EmailAnalysis)
        .where(EmailAnalysis.id == analysis_id)
        .options(
            selectinload(EmailAnalysis.iocs),
            selectinload(EmailAnalysis.attachments),
        )
    )
    analysis = result.scalar_one_or_none()
    if analysis is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")
    return analysis


async def _run_analysis(analysis_id: uuid.UUID, raw_bytes: bytes) -> None:
    """Background task: run full threat analysis pipeline."""
    from app.db.session import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        try:
            analysis = await db.get(EmailAnalysis, analysis_id)
            if analysis is None:
                return
            pipeline = ThreatAnalysisPipeline()
            await pipeline.run(db, analysis, raw_bytes)
            await db.commit()
        except Exception as e:
            logger.error("background_analysis_error", analysis_id=str(analysis_id), error=str(e))
            async with AsyncSessionLocal() as db2:
                analysis = await db2.get(EmailAnalysis, analysis_id)
                if analysis:
                    analysis.status = AnalysisStatus.FAILED
                    analysis.error_message = str(e)
                    await db2.commit()
