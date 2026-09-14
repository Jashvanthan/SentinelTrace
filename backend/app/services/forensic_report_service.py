"""
SentinelTrace Backend — Forensic Report Generation & Evidence Export Service
"""
from __future__ import annotations

import hashlib
import io
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.investigation import Investigation
from app.models.report import ForensicReport, ReportStatus
from app.services.audit_service import write_audit_log
from app.services.forensic_timeline_service import ForensicTimelineService
from app.services.intel_service import ThreatIntelService
from app.services.investigation_service import InvestigationService

settings = get_settings()
logger = get_logger("sentineltrace.forensic_report_service")


class ForensicReportService:
    """Master orchestrator for versioned, cryptographically-hashed forensic investigation reports."""

    @staticmethod
    def get_dynamic_limitations() -> list[str]:
        """
        Dynamically construct investigator limitations based on actual provider configuration.
        """
        limitations: list[str] = [
            "Geographic coordinates represent an approximate network-level location (ISP/datacenter) and do not establish physical location of a person or device.",
            "Inferred network hops are calculated from Received-headers and routing telemetry and do not imply direct physical route control.",
        ]

        if not settings.VIRUSTOTAL_API_KEY:
            limitations.append("Threat Intelligence: VirusTotal — NOT CONFIGURED (Public engine reputation was unqueried).")
        if not settings.ABUSEIPDB_API_KEY:
            limitations.append("Threat Intelligence: AbuseIPDB — NOT CONFIGURED (Crowdsourced abuse reports unqueried).")
        if not settings.SHODAN_API_KEY:
            limitations.append("Threat Intelligence: Shodan — NOT CONFIGURED (Open port/service vulnerability scanning unqueried).")
        if not settings.MAXMIND_CITY_DB_PATH:
            limitations.append("GeoIP Provider: MaxMind — NOT CONFIGURED (Using public failover GeoIP API).")

        limitations.append("Internal LAN Telemetry: NOT CONNECTED (Physical switch/port/MAC locations unavailable without enterprise connector).")
        return limitations

    @classmethod
    def compute_sha256_hash(cls, data: Any) -> str:
        """Calculate a deterministic SHA-256 hash of a JSON-serializable structure."""
        canonical_str = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    @classmethod
    async def create_report(
        cls,
        db: AsyncSession,
        workspace_id: uuid.UUID,
        investigation_id: uuid.UUID,
        user_id: uuid.UUID,
        title: str | None = None,
    ) -> ForensicReport:
        investigation = await InvestigationService.get_investigation(db, workspace_id, investigation_id)
        if not investigation:
            raise ValueError("Investigation not found")

        # Determine version number
        existing_count = (await db.scalar(
            select(func.count(ForensicReport.id)).where(
                ForensicReport.workspace_id == workspace_id,
                ForensicReport.investigation_id == investigation_id,
            )
        )) or 0

        next_version = existing_count + 1
        report_number = f"STR-INV-{str(investigation.id)[:8].upper()}-V{next_version}"
        report_title = title or f"Forensic Investigation Report: {investigation.name} (v{next_version})"

        # Capture complete immutable snapshot
        timeline = await ForensicTimelineService.build_campaign_timeline(db, workspace_id, investigation_id)
        limitations = cls.get_dynamic_limitations()

        snapshot: dict[str, Any] = {
            "investigation": {
                "id": str(investigation.id),
                "name": investigation.name,
                "description": investigation.description,
                "status": investigation.status.value,
                "created_at": investigation.created_at.isoformat(),
            },
            "risk_summary": getattr(investigation, "risk_summary", {}),
            "entities": [
                {
                    "id": str(e.id),
                    "type": e.entity_type,
                    "value": e.entity_value or e.entity_id,
                }
                for e in investigation.entities
            ],
            "notes": [
                {
                    "id": str(n.id),
                    "content": n.content,
                    "author_id": str(n.author_id),
                    "created_at": n.created_at.isoformat(),
                }
                for n in investigation.notes
            ],
            "findings": [
                {
                    "id": str(f.id),
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "evidence_references": f.evidence_references,
                }
                for f in investigation.findings
            ],
            "verifications": [
                {
                    "evidence_id": v.evidence_id,
                    "status": v.status.value,
                    "comment": v.comment,
                    "verified_at": v.verified_at.isoformat(),
                }
                for v in investigation.verifications
            ],
            "timeline": timeline,
        }

        # Calculate cryptographic hashes
        report_hash = cls.compute_sha256_hash(snapshot)
        evidence_root_hash = cls.compute_sha256_hash(snapshot.get("verifications", []))

        now_utc = datetime.now(UTC)

        report = ForensicReport(
            id=uuid.uuid4(),
            workspace_id=workspace_id,
            investigation_id=investigation_id,
            title=report_title,
            report_number=report_number,
            version=next_version,
            status=ReportStatus.READY,
            created_by_id=user_id,
            generated_at=now_utc,
            report_hash=report_hash,
            evidence_root_hash=evidence_root_hash,
            investigation_snapshot=snapshot,
            limitations_snapshot=limitations,
        )

        db.add(report)

        await write_audit_log(
            db=db,
            action="REPORT_GENERATED",
            user_id=user_id,
            resource_type="forensic_report",
            resource_id=str(report.id),
            details={"version": next_version, "report_hash": report_hash},
            outcome="SUCCESS",
        )
        await db.commit()
        return report

    @classmethod
    def generate_pdf_bytes(cls, report: ForensicReport) -> bytes:
        """
        Generate a multi-page PDF document for an investigation report snapshot.
        """
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        primary_color = colors.HexColor("#0f172a")
        accent_color = colors.HexColor("#3b82f6")
        muted_color = colors.HexColor("#64748b")
        light_bg = colors.HexColor("#f8fafc")
        border_color = colors.HexColor("#e2e8f0")

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=primary_color,
        )
        meta_style = ParagraphStyle(
            "DocMeta",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=muted_color,
        )
        heading_style = ParagraphStyle(
            "SectionHeading",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=primary_color,
        )
        body_style = ParagraphStyle(
            "BodyText",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=primary_color,
        )

        story: list[Any] = []

        # 1. Header
        story.append(Paragraph("SENTINELTRACE FORENSIC REPORT", meta_style))
        story.append(Spacer(1, 4))
        story.append(Paragraph(report.title, title_style))
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            f"Report Number: <b>{report.report_number}</b> | Version: <b>v{report.version}</b> | Generated: <b>{report.generated_at.isoformat() if report.generated_at else 'N/A'}</b>",
            meta_style,
        ))
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1, color=border_color, spaceAfter=12))

        # 2. Executive Summary
        snapshot = report.investigation_snapshot or {}
        risk = snapshot.get("risk_summary", {})
        story.append(Paragraph("1. EXECUTIVE SUMMARY & RISK ASSESSMENT", heading_style))
        story.append(Spacer(1, 6))

        summary_table_data = [
            [Paragraph("<b>Risk Score</b>", body_style), Paragraph(f"<b>{risk.get('risk_score', 0)} / 100</b> ({risk.get('severity', 'CLEAN')})", body_style)],
            [Paragraph("<b>Attached Entities</b>", body_style), Paragraph(str(len(snapshot.get("entities", []))), body_style)],
            [Paragraph("<b>Analyst Findings</b>", body_style), Paragraph(str(len(snapshot.get("findings", []))), body_style)],
            [Paragraph("<b>Cryptographic Hash (SHA-256)</b>", body_style), Paragraph(f"<font size=7>{report.report_hash or 'N/A'}</font>", body_style)],
        ]
        t = Table(summary_table_data, colWidths=[150, 390])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), light_bg),
            ("GRID", (0, 0), (-1, -1), 0.5, border_color),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(t)
        story.append(Spacer(1, 14))

        # 3. Analyst Findings
        story.append(Paragraph("2. ANALYST FINDINGS", heading_style))
        story.append(Spacer(1, 6))
        findings = snapshot.get("findings", [])
        if findings:
            f_data = [["Title", "Severity", "Confidence", "Description"]]
            for f in findings:
                raw_desc = f.get("description", "")[:120]
                clean_desc = raw_desc.replace("**", "").replace("*", "").strip()
                f_data.append([
                    Paragraph(f"<b>{f.get('title')}</b>", body_style),
                    f.get("severity", "MEDIUM"),
                    f.get("confidence", "HIGH"),
                    Paragraph(clean_desc, body_style),
                ])
            ft = Table(f_data, colWidths=[120, 60, 60, 300])
            ft.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), primary_color),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, border_color),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(ft)
        else:
            story.append(Paragraph("No analyst findings recorded.", meta_style))

        story.append(Spacer(1, 14))

        # 4. Limitations
        story.append(Paragraph("3. DYNAMIC INVESTIGATION LIMITATIONS", heading_style))
        story.append(Spacer(1, 6))
        for lim in (report.limitations_snapshot or []):
            story.append(Paragraph(f"&bull;&nbsp; {lim}", body_style))
            story.append(Spacer(1, 3))

        doc.build(story)
        return buf.getvalue()
