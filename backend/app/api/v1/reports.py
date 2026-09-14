"""
SentinelTrace Backend — Forensic Reporting & Evidence Export API Router
"""
from __future__ import annotations

import json
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select

from app.core.deps import CurrentUser, DbSession, require_workspace_role
from app.models.report import ForensicReport, ReportStatus
from app.schemas.report import ReportCreateRequest, ReportListResponse, ReportResponse
from app.services.audit_service import write_audit_log
from app.services.forensic_report_service import ForensicReportService

router = APIRouter(prefix="/workspaces/{workspace_id}/investigations/{investigation_id}/reports", tags=["Forensic Reporting & Evidence Export"])


@router.post("", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def generate_forensic_report(
    workspace_id: uuid.UUID,
    investigation_id: uuid.UUID,
    payload: ReportCreateRequest,
    db: DbSession,
    current_user: CurrentUser,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst"))],
):
    """Generate an immutable, versioned, cryptographically-hashed forensic investigation report snapshot."""
    try:
        report = await ForensicReportService.create_report(
            db=db,
            workspace_id=workspace_id,
            investigation_id=investigation_id,
            user_id=current_user.id,
            title=payload.title,
        )
        return ReportResponse.model_validate(report)
    except ValueError as err:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(err))


@router.get("", response_model=ReportListResponse)
async def list_reports(
    workspace_id: uuid.UUID,
    investigation_id: uuid.UUID,
    db: DbSession,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst", "viewer"))],
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """List all generated report versions for an investigation."""
    query = (
        select(ForensicReport)
        .where(
            ForensicReport.workspace_id == workspace_id,
            ForensicReport.investigation_id == investigation_id,
        )
        .order_by(ForensicReport.version.desc())
        .limit(limit)
        .offset(offset)
    )
    items = (await db.execute(query)).scalars().all()
    total = len(items)

    return ReportListResponse(
        items=[ReportResponse.model_validate(r) for r in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report_by_id(
    workspace_id: uuid.UUID,
    investigation_id: uuid.UUID,
    report_id: uuid.UUID,
    db: DbSession,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst", "viewer"))],
):
    """Get report details and cryptographic hash values."""
    report = await db.scalar(
        select(ForensicReport).where(
            ForensicReport.id == report_id,
            ForensicReport.investigation_id == investigation_id,
            ForensicReport.workspace_id == workspace_id,
        )
    )
    if not report:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report version not found in workspace")
    return ReportResponse.model_validate(report)


@router.get("/{report_id}/pdf")
async def download_report_pdf(
    workspace_id: uuid.UUID,
    investigation_id: uuid.UUID,
    report_id: uuid.UUID,
    db: DbSession,
    current_user: CurrentUser,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst", "viewer"))],
):
    """Download executive PDF report for a generated investigation snapshot."""
    report = await db.scalar(
        select(ForensicReport).where(
            ForensicReport.id == report_id,
            ForensicReport.investigation_id == investigation_id,
            ForensicReport.workspace_id == workspace_id,
        )
    )
    if not report:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")

    pdf_bytes = ForensicReportService.generate_pdf_bytes(report)

    await write_audit_log(
        db=db,
        action="REPORT_EXPORTED_PDF",
        user_id=current_user.id,
        resource_type="forensic_report",
        resource_id=str(report_id),
        details={"report_number": report.report_number},
        outcome="SUCCESS",
    )
    await db.commit()

    filename = f"{report.report_number.lower()}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{report_id}/json")
async def download_report_json(
    workspace_id: uuid.UUID,
    investigation_id: uuid.UUID,
    report_id: uuid.UUID,
    db: DbSession,
    current_user: CurrentUser,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst", "viewer"))],
):
    """Export machine-readable JSON forensic report snapshot."""
    report = await db.scalar(
        select(ForensicReport).where(
            ForensicReport.id == report_id,
            ForensicReport.investigation_id == investigation_id,
            ForensicReport.workspace_id == workspace_id,
        )
    )
    if not report:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")

    export_data = {
        "report_metadata": {
            "report_id": str(report.id),
            "workspace_id": str(report.workspace_id),
            "investigation_id": str(report.investigation_id),
            "report_number": report.report_number,
            "version": report.version,
            "status": report.status.value,
            "generated_at": report.generated_at.isoformat() if report.generated_at else None,
            "cryptographic_integrity": {
                "algorithm": "SHA-256",
                "report_hash": report.report_hash,
                "evidence_root_hash": report.evidence_root_hash,
            },
        },
        "investigation_snapshot": report.investigation_snapshot,
        "dynamic_limitations": report.limitations_snapshot,
    }

    await write_audit_log(
        db=db,
        action="REPORT_EXPORTED_JSON",
        user_id=current_user.id,
        resource_type="forensic_report",
        resource_id=str(report_id),
        details={"report_number": report.report_number},
        outcome="SUCCESS",
    )
    await db.commit()

    filename = f"{report.report_number.lower()}.json"
    json_bytes = json.dumps(export_data, indent=2).encode("utf-8")
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
