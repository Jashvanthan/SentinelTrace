"""
SentinelTrace Backend — Analyst Investigation Workspace API Router
"""
from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select

from app.core.deps import CurrentUser, DbSession, require_workspace_role
from app.models.investigation import (
    AnalystFinding,
    AnalystNote,
    EvidenceVerification,
    Investigation,
    InvestigationEntity,
    InvestigationStatus,
)
from app.schemas.investigation import (
    AnalystFindingResponse,
    AnalystNoteResponse,
    EntityAttachRequest,
    EvidenceVerificationResponse,
    EvidenceVerifyRequest,
    FindingCreate,
    InvestigationCreate,
    InvestigationEntityResponse,
    InvestigationListResponse,
    InvestigationResponse,
    InvestigationUpdate,
    NoteCreate,
)
from app.services.audit_service import write_audit_log
from app.services.forensic_timeline_service import ForensicTimelineService
from app.services.investigation_service import InvestigationService
from app.services.neo4j_service import get_neo4j_service

router = APIRouter(prefix="/workspaces/{workspace_id}/investigations", tags=["Analyst Investigation Workspace"])


@router.post("", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
async def create_investigation(
    workspace_id: uuid.UUID,
    payload: InvestigationCreate,
    db: DbSession,
    current_user: CurrentUser,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst"))],
):
    """Create a new analyst investigation case file."""
    investigation = await InvestigationService.create_investigation(
        db=db,
        workspace_id=workspace_id,
        user_id=current_user.id,
        name=payload.name,
        description=payload.description,
        starting_entity_type=payload.starting_entity_type,
        starting_entity_id=payload.starting_entity_id,
        starting_entity_value=payload.starting_entity_value,
    )
    return InvestigationResponse.model_validate(investigation)


@router.get("", response_model=InvestigationListResponse)
async def list_investigations(
    workspace_id: uuid.UUID,
    db: DbSession,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst", "viewer"))],
    status_filter: InvestigationStatus | None = Query(None, alias="status"),
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """List investigations for the workspace."""
    items, total = await InvestigationService.list_investigations(
        db=db,
        workspace_id=workspace_id,
        status=status_filter,
        limit=limit,
        offset=offset,
    )
    return InvestigationListResponse(
        items=[InvestigationResponse.model_validate(inv) for inv in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation_by_id(
    workspace_id: uuid.UUID,
    investigation_id: uuid.UUID,
    db: DbSession,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst", "viewer"))],
):
    """Retrieve detailed investigation case file with entities, notes, findings, and verifications."""
    investigation = await InvestigationService.get_investigation(db, workspace_id, investigation_id)
    if not investigation:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found in workspace")
    return InvestigationResponse.model_validate(investigation)


@router.patch("/{investigation_id}", response_model=InvestigationResponse)
async def update_investigation(
    workspace_id: uuid.UUID,
    investigation_id: uuid.UUID,
    payload: InvestigationUpdate,
    db: DbSession,
    current_user: CurrentUser,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst"))],
):
    """Update investigation metadata or status."""
    investigation = await InvestigationService.get_investigation(db, workspace_id, investigation_id)
    if not investigation:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found in workspace")

    if payload.name:
        investigation.name = payload.name
    if payload.description is not None:
        investigation.description = payload.description
    if payload.status:
        await InvestigationService.update_investigation_status(
            db, workspace_id, current_user.id, investigation_id, payload.status
        )

    await db.commit()
    return await get_investigation_by_id(workspace_id, investigation_id, db, member)


@router.post("/{investigation_id}/entities", response_model=InvestigationEntityResponse)
async def attach_entity(
    workspace_id: uuid.UUID,
    investigation_id: uuid.UUID,
    payload: EntityAttachRequest,
    db: DbSession,
    current_user: CurrentUser,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst"))],
):
    """Attach an existing email, IOC, IP, domain, URL, hash, or campaign entity reference to the case file."""
    investigation = await InvestigationService.get_investigation(db, workspace_id, investigation_id)
    if not investigation:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found in workspace")

    entity = InvestigationEntity(
        id=uuid.uuid4(),
        workspace_id=workspace_id,
        investigation_id=investigation_id,
        entity_type=payload.entity_type.upper(),
        entity_id=payload.entity_id,
        entity_value=payload.entity_value,
        added_by_id=current_user.id,
    )
    db.add(entity)

    await write_audit_log(
        db=db,
        action="ENTITY_ADDED",
        user_id=current_user.id,
        resource_type="investigation",
        resource_id=str(investigation_id),
        details={"entity_type": payload.entity_type, "entity_id": payload.entity_id},
        outcome="SUCCESS",
    )
    await db.commit()
    return InvestigationEntityResponse.model_validate(entity)


@router.delete("/{investigation_id}/entities/{entity_id}")
async def remove_entity(
    workspace_id: uuid.UUID,
    investigation_id: uuid.UUID,
    entity_id: uuid.UUID,
    db: DbSession,
    current_user: CurrentUser,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst"))],
):
    """Remove attached entity reference from investigation case file."""
    entity = await db.scalar(
        select(InvestigationEntity).where(
            InvestigationEntity.id == entity_id,
            InvestigationEntity.investigation_id == investigation_id,
            InvestigationEntity.workspace_id == workspace_id,
        )
    )
    if not entity:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Attached entity not found")

    await db.delete(entity)
    await write_audit_log(
        db=db,
        action="ENTITY_REMOVED",
        user_id=current_user.id,
        resource_type="investigation",
        resource_id=str(investigation_id),
        details={"entity_id": str(entity_id)},
        outcome="SUCCESS",
    )
    await db.commit()
    return {"status": "SUCCESS", "message": "Entity unlinked from investigation"}


@router.post("/{investigation_id}/notes", response_model=AnalystNoteResponse)
async def add_analyst_note(
    workspace_id: uuid.UUID,
    investigation_id: uuid.UUID,
    payload: NoteCreate,
    db: DbSession,
    current_user: CurrentUser,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst"))],
):
    """Add workspace-isolated analyst note to the investigation case file."""
    investigation = await InvestigationService.get_investigation(db, workspace_id, investigation_id)
    if not investigation:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found in workspace")

    note = AnalystNote(
        id=uuid.uuid4(),
        workspace_id=workspace_id,
        investigation_id=investigation_id,
        author_id=current_user.id,
        content=payload.content,
    )
    db.add(note)

    await write_audit_log(
        db=db,
        action="NOTE_CREATED",
        user_id=current_user.id,
        resource_type="investigation",
        resource_id=str(investigation_id),
        details={"note_id": str(note.id)},
        outcome="SUCCESS",
    )
    await db.commit()
    return AnalystNoteResponse.model_validate(note)


@router.post("/{investigation_id}/findings", response_model=AnalystFindingResponse)
async def add_analyst_finding(
    workspace_id: uuid.UUID,
    investigation_id: uuid.UUID,
    payload: FindingCreate,
    db: DbSession,
    current_user: CurrentUser,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst"))],
):
    """Add structured analyst finding backed by evidence references."""
    investigation = await InvestigationService.get_investigation(db, workspace_id, investigation_id)
    if not investigation:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found in workspace")

    finding = AnalystFinding(
        id=uuid.uuid4(),
        workspace_id=workspace_id,
        investigation_id=investigation_id,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        confidence=payload.confidence,
        evidence_references=payload.evidence_references,
        created_by_id=current_user.id,
    )
    db.add(finding)

    await write_audit_log(
        db=db,
        action="FINDING_CREATED",
        user_id=current_user.id,
        resource_type="investigation",
        resource_id=str(investigation_id),
        details={"title": payload.title, "severity": payload.severity.value},
        outcome="SUCCESS",
    )
    await db.commit()
    return AnalystFindingResponse.model_validate(finding)


@router.post("/{investigation_id}/evidence/{evidence_id}/verify", response_model=EvidenceVerificationResponse)
async def verify_evidence_item(
    workspace_id: uuid.UUID,
    investigation_id: uuid.UUID,
    evidence_id: str,
    payload: EvidenceVerifyRequest,
    db: DbSession,
    current_user: CurrentUser,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst"))],
):
    """Mark an evidence item as REVIEWED, VERIFIED, or DISPUTED with explicit analyst attribution."""
    investigation = await InvestigationService.get_investigation(db, workspace_id, investigation_id)
    if not investigation:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found in workspace")

    verification = await db.scalar(
        select(EvidenceVerification).where(
            EvidenceVerification.workspace_id == workspace_id,
            EvidenceVerification.investigation_id == investigation_id,
            EvidenceVerification.evidence_id == evidence_id,
        )
    )
    if verification:
        verification.status = payload.status
        verification.comment = payload.comment
        verification.verified_by_id = current_user.id
    else:
        verification = EvidenceVerification(
            id=uuid.uuid4(),
            workspace_id=workspace_id,
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            status=payload.status,
            verified_by_id=current_user.id,
            comment=payload.comment,
        )
        db.add(verification)

    await write_audit_log(
        db=db,
        action="EVIDENCE_VERIFIED",
        user_id=current_user.id,
        resource_type="investigation",
        resource_id=str(investigation_id),
        details={"evidence_id": evidence_id, "status": payload.status.value},
        outcome="SUCCESS",
    )
    await db.commit()
    return EvidenceVerificationResponse.model_validate(verification)


@router.get("/{investigation_id}/graph")
async def get_investigation_graph(
    workspace_id: uuid.UUID,
    investigation_id: uuid.UUID,
    db: DbSession,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst", "viewer"))],
    depth: int = Query(2, ge=1, le=4),
):
    """Retrieve workspace-isolated multi-hop graph bounded by depth limit."""
    investigation = await InvestigationService.get_investigation(db, workspace_id, investigation_id)
    if not investigation:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found in workspace")

    neo4j = get_neo4j_service()
    graph = await neo4j.get_campaign_graph(
        workspace_id=str(workspace_id),
        depth=depth,
    )
    return graph


@router.get("/{investigation_id}/timeline")
async def get_investigation_timeline(
    workspace_id: uuid.UUID,
    investigation_id: uuid.UUID,
    db: DbSession,
    member: Annotated[object, Depends(require_workspace_role("owner", "admin", "analyst", "viewer"))],
):
    """Get UTC chronological investigation timeline of all attached entities and analyst actions."""
    investigation = await InvestigationService.get_investigation(db, workspace_id, investigation_id)
    if not investigation:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found in workspace")

    events: list[dict[str, Any]] = [
        {
            "id": f"inv-created-{investigation.id}",
            "timestamp": investigation.created_at.isoformat(),
            "event_type": "INVESTIGATION_CREATED",
            "title": f"Investigation '{investigation.name}' Opened",
            "description": f"Case file created by analyst",
            "source": "Analyst Action",
            "entity_type": "INVESTIGATION",
            "confidence": "HIGH",
        }
    ]

    for note in investigation.notes:
        events.append({
            "id": f"note-{note.id}",
            "timestamp": note.created_at.isoformat(),
            "event_type": "ANALYST_NOTE_ADDED",
            "title": "Analyst Note Added",
            "description": note.content[:100],
            "source": "Analyst Note",
            "entity_type": "NOTE",
            "confidence": "HIGH",
        })

    for finding in investigation.findings:
        events.append({
            "id": f"finding-{finding.id}",
            "timestamp": finding.created_at.isoformat(),
            "event_type": "ANALYST_FINDING_CREATED",
            "title": f"Finding: {finding.title}",
            "description": f"Severity: {finding.severity.value} | Confidence: {finding.confidence.value}",
            "source": "Analyst Finding",
            "entity_type": "FINDING",
            "confidence": finding.confidence.value,
        })

    for v in investigation.verifications:
        events.append({
            "id": f"verification-{v.id}",
            "timestamp": v.verified_at.isoformat(),
            "event_type": "EVIDENCE_VERIFIED",
            "title": f"Evidence Status: {v.status.value}",
            "description": v.comment or f"Evidence {v.evidence_id} marked as {v.status.value}",
            "source": "Analyst Verification",
            "entity_type": "VERIFICATION",
            "confidence": "HIGH",
        })

    events.sort(key=lambda x: x["timestamp"])
    return {"investigation_id": str(investigation_id), "workspace_id": str(workspace_id), "timeline": events}
