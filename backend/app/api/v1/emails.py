"""
SentinelTrace Backend — Email Analysis API Router

Endpoints:
  POST /emails/upload              Upload .eml file → trigger analysis
  GET  /emails/                    List analyses (paginated, filterable, workspace-scoped)
  GET  /emails/{id}                Get full analysis detail
  GET  /emails/{id}/report         Get signed GCS URL for evidence report
  DELETE /emails/{id}              Delete an analysis
  GET  /emails/{id}/status         SSE stream for real-time status updates

Security note (Step 14 fix)
----------------------------
All list/detail queries are now workspace-scoped.  The client supplies a
``workspace_id`` query parameter; the backend verifies the authenticated user
is a member of that workspace via ``require_workspace_role()`` before executing
any database query.  Individual analysis detail requests additionally verify
that the record belongs to the authorised workspace.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select

from app.core.deps import AnalystOrAbove, CurrentUser, DbSession, require_workspace_role
from app.core.logging import get_logger
from app.models.email_analysis import AnalysisStatus, EmailAnalysis, SeverityLevel, ThreatCategory
from app.models.workspace import WorkspaceMember
from app.schemas.email_analysis import (
    AnalysisTriggerResponse,
    EmailAnalysisDetail,
    EmailAnalysisListResponse,
    EmailAnalysisSummary,
    EmailObservedIPsResponse,
    ObservedIPItem,
)
from app.services.threat_service import ThreatAnalysisPipeline
from app.services.audit_service import write_audit_log

router = APIRouter(prefix="/emails", tags=["Email Analysis"])
logger = get_logger("sentineltrace.api.emails")

MAX_EML_SIZE = 50 * 1024 * 1024  # 50 MB


@router.post("/upload", response_model=AnalysisTriggerResponse, status_code=status.HTTP_202_ACCEPTED)
async def upload_email(
    background_tasks: BackgroundTasks,
    db: DbSession,
    current_user: CurrentUser,
    member: Annotated[WorkspaceMember, Depends(require_workspace_role("owner", "admin", "analyst"))],
    file: UploadFile = File(..., description="Raw .eml file"),
    notes: str | None = Form(None),
    priority: str = Form("NORMAL"),
    workspace_id: uuid.UUID | None = Query(None, description="Workspace this email belongs to"),
):
    """
    Upload a raw .eml file and trigger asynchronous threat analysis.

    The file is validated, initial deterministic headers/hashes are stored,
    and analysis is queued in Celery background worker. Returns HTTP 202 Accepted immediately.
    """
    from app.services.email_service import parse_eml
    from app.worker import analyze_uploaded_eml

    target_workspace_id = workspace_id or member.workspace_id

    # Validate file
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Only .eml files are accepted")

    raw_bytes = await file.read()
    if len(raw_bytes) == 0:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty file")
    if len(raw_bytes) > MAX_EML_SIZE:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File exceeds 50 MB limit")

    # Fast deterministic parse for initial record metadata
    parsed = parse_eml(raw_bytes)
    pipeline_helper = ThreatAnalysisPipeline()

    # Create analysis record scoped to the authorised workspace
    analysis = EmailAnalysis(
        workspace_id=target_workspace_id,
        analyst_id=current_user.id,
        status=AnalysisStatus.PENDING,
        source_provider="upload",
        subject=parsed.subject,
        sender_email=parsed.sender_email,
        sender_display_name=parsed.sender_display_name,
        sender_domain=parsed.sender_domain,
        reply_to=parsed.reply_to,
        recipients=parsed.recipients,
        message_id=parsed.message_id,
        email_date=pipeline_helper._parse_email_date(parsed.email_date),
        received_headers=parsed.received_headers,
        all_headers=parsed.all_headers,
        authentication_results=parsed.authentication_results,
        spf_result=parsed.spf_result,
        dkim_result=parsed.dkim_result,
        dmarc_result=parsed.dmarc_result,
        raw_eml_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        raw_eml_size_bytes=len(raw_bytes),
    )
    db.add(analysis)
    await db.commit()
    await db.refresh(analysis)
    analysis_id = analysis.id

    logger.info(
        "email_uploaded_queued",
        analysis_id=str(analysis_id),
        workspace_id=str(target_workspace_id),
    )

    # Queue asynchronous background analysis via Celery
    try:
        analyze_uploaded_eml.delay(str(target_workspace_id), str(analysis_id), raw_bytes.hex())
    except Exception as queue_err:
        logger.warning(f"Could not dispatch Celery task, falling back to background_tasks: {queue_err}")
        background_tasks.add_task(pipeline_helper.run, db, analysis, raw_bytes)

    await write_audit_log(
        db,
        action="EMAIL_UPLOADED",
        user_id=current_user.id,
        resource_type="email_analysis",
        resource_id=str(analysis_id),
        details={"subject": analysis.subject, "sha256": analysis.raw_eml_sha256},
        outcome="SUCCESS",
    )
    await db.commit()

    return AnalysisTriggerResponse(
        analysis_id=analysis_id,
        status=analysis.status,
        message="Email uploaded and analysis queued successfully.",
    )


@router.post("/{analysis_id}/analyze", response_model=AnalysisTriggerResponse, status_code=status.HTTP_202_ACCEPTED)
async def analyze_email_on_demand(
    background_tasks: BackgroundTasks,
    analysis_id: uuid.UUID,
    db: DbSession,
    current_user: CurrentUser,
    member: Annotated[WorkspaceMember, Depends(require_workspace_role("owner", "admin", "analyst", "editor"))],
    workspace_id: uuid.UUID | None = Query(None, description="Workspace the analysis belongs to"),
):
    """
    Queue asynchronous forensic threat analysis on-demand for a stored/fetched email.
    
    Guarantees idempotency and strict workspace isolation (BOLA/IDOR protection).
    """
    target_ws = workspace_id or (member.workspace_id if member else None)
    analysis = await _get_or_404(db, analysis_id, workspace_id=target_ws)

    # If already complete and analyzed, return without creating duplicate jobs
    if analysis.status == AnalysisStatus.COMPLETE and analysis.threat_score is not None:
        return AnalysisTriggerResponse(
            analysis_id=analysis.id,
            status=analysis.status,
            message="Email has already been analyzed.",
        )

    # If already actively processing, return 202 without creating duplicate jobs
    if analysis.status == AnalysisStatus.PROCESSING:
        return AnalysisTriggerResponse(
            analysis_id=analysis.id,
            status=analysis.status,
            message="Forensic analysis is already in progress.",
        )

    # Set status to PROCESSING
    analysis.status = AnalysisStatus.PROCESSING
    await db.commit()
    await db.refresh(analysis)

    # Dispatch worker task (Celery + Asyncio fallback)
    try:
        from app.worker import analyze_email_job, _async_analyze_email_job
        try:
            analyze_email_job.delay(str(analysis.workspace_id), str(analysis.id))
        except Exception:
            background_tasks.add_task(
                _async_analyze_email_job, None, str(analysis.workspace_id), str(analysis.id)
            )
    except Exception as queue_err:
        logger.warning(f"Could not dispatch on-demand analysis: {queue_err}")

    await write_audit_log(
        db,
        action="EMAIL_ANALYSIS_REQUESTED",
        user_id=current_user.id,
        resource_type="email_analysis",
        resource_id=str(analysis_id),
        details={"subject": analysis.subject},
        outcome="SUCCESS",
    )
    await db.commit()

    return AnalysisTriggerResponse(
        analysis_id=analysis.id,
        status=analysis.status,
        message="Email analysis queued successfully.",
    )


@router.get("/", response_model=EmailAnalysisListResponse)
async def list_analyses(
    db: DbSession,
    current_user: CurrentUser,
    member: Annotated[WorkspaceMember, Depends(require_workspace_role())],
    workspace_id: uuid.UUID | None = Query(None, description="Workspace to scope results to"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    status_filter: AnalysisStatus | None = Query(None, alias="status"),
    severity_filter: SeverityLevel | None = Query(None, alias="severity"),
    threat_category: ThreatCategory | None = Query(None),
    source_filter: str | None = Query(None, alias="source", description="Filter by ingestion source ('upload' or 'google')"),
    search: str | None = Query(None, max_length=256),
):
    """
    List email analyses with pagination and filtering.

    Workspace isolation: the ``workspace_id`` query parameter is validated
    against the authenticated user's membership before any data is returned.
    Only analyses belonging to the authorised workspace are included.
    """
    if not workspace_id:
        workspace_id = member.workspace_id if member else None

    # Always scope to the authorised workspace — never trust the param alone
    q = select(EmailAnalysis).where(EmailAnalysis.workspace_id == workspace_id)

    if status_filter:
        q = q.where(EmailAnalysis.status == status_filter)
    if severity_filter:
        q = q.where(EmailAnalysis.severity == severity_filter)
    if threat_category:
        q = q.where(EmailAnalysis.threat_category == threat_category)
    if source_filter:
        if source_filter.lower() in ("upload", "eml", "manual"):
            q = q.where((EmailAnalysis.source_provider == "upload") | (EmailAnalysis.source_provider.is_(None)))
        elif source_filter.lower() in ("google", "gmail"):
            q = q.where(EmailAnalysis.source_provider.in_(["google", "gmail"]))
        else:
            q = q.where(EmailAnalysis.source_provider == source_filter)
    if search:
        q = q.where(
            EmailAnalysis.subject.ilike(f"%{search}%")
            | EmailAnalysis.sender_email.ilike(f"%{search}%")
            | EmailAnalysis.sender_domain.ilike(f"%{search}%")
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


def _normalize_raw_ip(raw: str) -> str:
    clean = raw.strip()
    parts = clean.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        try:
            return ".".join(str(int(p)) for p in parts)
        except ValueError:
            pass
    return clean


def classify_ip_candidate(raw: str) -> tuple[str, str, bool]:
    """
    Returns (normalized_ip, classification, is_private).
    is_private is True only if the IP cannot be geolocated publicly (RFC 1918, loopback, link-local, unspecified, multicast).
    RFC 5737 test documentation addresses are considered public/testable.
    """
    norm = _normalize_raw_ip(raw)
    try:
        addr = ipaddress.ip_address(norm)
    except ValueError:
        return norm, "INVALID", True

    if addr.is_loopback:
        return str(addr), "LOOPBACK", True
    if addr.is_loopback:
        return str(addr), "LOOPBACK", True
    if addr.is_link_local:
        return str(addr), "LINK_LOCAL", True
    if addr.is_multicast:
        return str(addr), "MULTICAST", True
    if addr.is_unspecified:
        return str(addr), "UNSPECIFIED", True

    if isinstance(addr, ipaddress.IPv4Address):
        if (
            addr in ipaddress.ip_network("192.0.2.0/24")
            or addr in ipaddress.ip_network("198.51.100.0/24")
            or addr in ipaddress.ip_network("203.0.113.0/24")
        ):
            return str(addr), "DOCUMENTATION", False
        if addr in ipaddress.ip_network("240.0.0.0/4"):
            return str(addr), "RESERVED", True

    if addr.is_private:
        return str(addr), "PRIVATE", True
    if addr.is_reserved:
        return str(addr), "RESERVED", True

    return str(addr), "PUBLIC", False


def _normalize_analysis_geo_data(geo_data: dict | None) -> dict | None:
    """Ensure geo_data presents top-level location, ISP, ASN, and origin IP attributes."""
    if not geo_data or not isinstance(geo_data, dict):
        return None

    if geo_data.get("country") or geo_data.get("isp") or geo_data.get("ip_address"):
        return geo_data

    ips = geo_data.get("ips")
    if isinstance(ips, list) and len(ips) > 0:
        primary = None
        for g in ips:
            if isinstance(g, dict) and g.get("country") and g.get("routing_type") not in ("INTERNAL_LAN", "UNKNOWN") and not g.get("error"):
                primary = g
                break
        if not primary:
            for g in ips:
                if isinstance(g, dict) and g.get("routing_type") != "INTERNAL_LAN":
                    primary = g
                    break
        if not primary and ips:
            primary = ips[0] if isinstance(ips[0], dict) else None

        if primary:
            return {
                **primary,
                "ips": ips,
                "primary_ip": primary.get("ip_address"),
            }
    return geo_data


def _normalize_analysis_enrichment_data(enrichment_data: dict | None, primary_ip: str | None = None) -> dict | None:
    """Ensure enrichment_data presents top-level VirusTotal, AbuseIPDB, and Shodan provider telemetry."""
    if not enrichment_data or not isinstance(enrichment_data, dict):
        return None

    if enrichment_data.get("virustotal") or enrichment_data.get("abuseipdb") or enrichment_data.get("shodan"):
        return enrichment_data

    target_enrich = None
    if primary_ip and f"ip_{primary_ip}" in enrichment_data:
        target_enrich = enrichment_data[f"ip_{primary_ip}"]

    if not target_enrich:
        for k, v in enrichment_data.items():
            if k.startswith("ip_") and isinstance(v, dict) and v.get("providers"):
                target_enrich = v
                break

    if target_enrich and isinstance(target_enrich, dict):
        providers = target_enrich.get("providers", {})
        return {
            **enrichment_data,
            "virustotal": providers.get("virustotal"),
            "abuseipdb": providers.get("abuseipdb"),
            "shodan": providers.get("shodan"),
        }
    return enrichment_data


def _extract_observed_ips_from_analysis(analysis: EmailAnalysis) -> list[ObservedIPItem]:
    """Extract and classify all observed IP candidates from an EmailAnalysis."""
    observed_ips: list[ObservedIPItem] = []
    seen_ips: set[str] = set()

    # 1. Received headers (Transit hops)
    if analysis.received_headers:
        for idx, header in enumerate(analysis.received_headers):
            raw_ips = re.findall(r'(?:\[|\b)((?:\d{1,3}\.){3}\d{1,3}|[a-fA-F0-9:]{3,39})(?:\]|\b)', str(header))
            for raw_ip in raw_ips:
                try:
                    ip_str, classification, is_priv = classify_ip_candidate(raw_ip)
                    if classification == "INVALID":
                        continue
                    if ip_str not in seen_ips:
                        seen_ips.add(ip_str)
                        observed_ips.append(
                            ObservedIPItem(
                                ip_address=ip_str,
                                source="received_hop",
                                hop_number=idx + 1,
                                is_private=is_priv,
                                classification=classification,
                                description=f"Received transit hop #{idx + 1}",
                            )
                        )
                except Exception:
                    continue

    # 2. Origin headers in analysis.all_headers (e.g. x-originating-ip, x-sender-ip, x-client-ip)
    all_hdrs = getattr(analysis, "all_headers", None)
    if all_hdrs and isinstance(all_hdrs, dict):
        for h_name in ("x-originating-ip", "x-sender-ip", "x-client-ip", "X-Originating-IP", "X-Sender-IP", "X-Client-IP"):
            val = all_hdrs.get(h_name)
            if val and isinstance(val, str):
                raw_ips = re.findall(r'(?:\[|\b)((?:\d{1,3}\.){3}\d{1,3}|[a-fA-F0-9:]{3,39})(?:\]|\b)', val)
                for rip in raw_ips:
                    try:
                        ip_str, classification, is_priv = classify_ip_candidate(rip)
                        if classification != "INVALID" and ip_str not in seen_ips:
                            seen_ips.add(ip_str)
                            observed_ips.append(
                                ObservedIPItem(
                                    ip_address=ip_str,
                                    source="origin_header",
                                    hop_number=None,
                                    is_private=is_priv,
                                    classification=classification,
                                    description=f"Header: {h_name}",
                                )
                            )
                    except Exception:
                        pass

    # 3. Geo data records & ips list
    if analysis.geo_data and isinstance(analysis.geo_data, dict):
        for item in analysis.geo_data.get("ips", []):
            if isinstance(item, dict) and item.get("ip_address"):
                try:
                    ip_str, classification, is_priv = classify_ip_candidate(item["ip_address"])
                    if classification != "INVALID" and ip_str not in seen_ips:
                        seen_ips.add(ip_str)
                        observed_ips.append(
                            ObservedIPItem(
                                ip_address=ip_str,
                                source="geo_telemetry",
                                hop_number=item.get("hop_number"),
                                is_private=is_priv,
                                classification=classification,
                                description=item.get("routing_label") or "Observed Email Transit IP",
                            )
                        )
                except Exception:
                    pass

        raw_ip = analysis.geo_data.get("ip_address") or analysis.geo_data.get("primary_ip")
        if raw_ip and isinstance(raw_ip, str):
            try:
                ip_str, classification, is_priv = classify_ip_candidate(raw_ip)
                if classification != "INVALID" and ip_str not in seen_ips:
                    seen_ips.add(ip_str)
                    observed_ips.append(
                        ObservedIPItem(
                            ip_address=ip_str,
                            source="origin_header",
                            hop_number=None,
                            is_private=is_priv,
                            classification=classification,
                            description="Sender Origin Header IP",
                        )
                    )
            except Exception:
                pass

    # 4. Extracted IOCs (type IP_ADDRESS or IP)
    safe_iocs = getattr(analysis, "__dict__", {}).get("iocs") or []
    for ioc in safe_iocs:
        ioc_type = str(getattr(ioc, "ioc_type", "") if not isinstance(ioc, dict) else ioc.get("ioc_type", "")).upper()
        ioc_val = str(getattr(ioc, "value", "") if not isinstance(ioc, dict) else ioc.get("value", ""))
        if ioc_type in ("IP_ADDRESS", "IP", "IPADDRESS"):
            try:
                ip_str, classification, is_priv = classify_ip_candidate(ioc_val)
                if classification != "INVALID" and ip_str not in seen_ips:
                    seen_ips.add(ip_str)
                    observed_ips.append(
                        ObservedIPItem(
                            ip_address=ip_str,
                            source="extracted_ioc",
                            hop_number=None,
                            is_private=is_priv,
                            classification=classification,
                            description="Forensic Extracted IOC",
                        )
                    )
            except Exception:
                pass

    # 5. Fallback: Sender Domain DNS resolution if no IPs found yet
    if not observed_ips and analysis.sender_domain:
        import socket
        try:
            domain_clean = analysis.sender_domain.strip().lower()
            if domain_clean and not domain_clean.endswith(".local") and not domain_clean.endswith(".lan"):
                resolved_ip = socket.gethostbyname(domain_clean)
                ip_str, classification, is_priv = classify_ip_candidate(resolved_ip)
                if classification != "INVALID" and ip_str not in seen_ips:
                    seen_ips.add(ip_str)
                    observed_ips.append(
                        ObservedIPItem(
                            ip_address=ip_str,
                            source="sender_domain_dns",
                            hop_number=None,
                            is_private=is_priv,
                            classification=classification,
                            description=f"Sender Domain Server ({analysis.sender_domain})",
                        )
                    )
        except Exception:
            pass

    return observed_ips


def _build_diagnostic_status(
    analysis: EmailAnalysis,
    norm_geo: dict | None,
    norm_enrich: dict | None,
    observed_ips: list[ObservedIPItem],
) -> dict:
    public_ips = [item for item in observed_ips if not item.is_private]

    if len(observed_ips) == 0:
        ip_status = "NO_IP_OBSERVED"
        geo_status = "NO_DATA"
        intel_status = "NO_DATA"
        primary_ip = None
        classification = "UNSPECIFIED"
    elif len(public_ips) == 0:
        ip_status = "ONLY_PRIVATE_IPS"
        geo_status = "PRIVATE_IP"
        intel_status = "NOT_APPLICABLE"
        primary_ip = observed_ips[0].ip_address
        classification = observed_ips[0].classification
    else:
        ip_status = "PUBLIC_IP_AVAILABLE"
        primary_ip = public_ips[0].ip_address
        classification = public_ips[0].classification
        if norm_geo and norm_geo.get("country") and norm_geo.get("country") != "Unknown":
            geo_status = "SUCCESS"
        elif norm_geo and norm_geo.get("error"):
            geo_status = "PROVIDER_UNAVAILABLE"
        else:
            geo_status = "NO_DATA"

        if norm_enrich and (norm_enrich.get("virustotal") or norm_enrich.get("abuseipdb")):
            intel_status = "AVAILABLE"
        else:
            intel_status = "NO_DATA"

    return {
        "ip": primary_ip,
        "classification": classification,
        "ip_status": ip_status,
        "geolocation": {
            "status": geo_status,
            "provider": norm_geo.get("provider") if norm_geo else None,
        },
        "threat_intelligence": {
            "status": intel_status,
        },
    }


@router.get("/{analysis_id}", response_model=EmailAnalysisDetail)
async def get_analysis(
    analysis_id: uuid.UUID,
    db: DbSession,
    current_user: CurrentUser,
    member: Annotated[WorkspaceMember, Depends(require_workspace_role())],
    workspace_id: uuid.UUID | None = Query(None, description="Workspace the analysis belongs to"),
):
    """
    Get full analysis detail including IOCs, attachments, and AI summary.

    Workspace isolation: verifies the analysis belongs to the authorised workspace,
    preventing cross-workspace record enumeration (BOLA).
    """
    target_ws = workspace_id or (member.workspace_id if member else None)
    analysis = await _get_or_404(db, analysis_id, workspace_id=target_ws)

    # Ensure SPF / DKIM / DMARC are properly populated with valid verdicts if already analyzed
    if analysis.status == AnalysisStatus.COMPLETE and (analysis.spf_result is None or analysis.dmarc_result is None or analysis.dkim_result is None) and analysis.sender_domain:
        try:
            from app.services.email_service import check_domain_email_auth_dns
            dns_auth = check_domain_email_auth_dns(analysis.sender_domain)
            if analysis.spf_result is None:
                analysis.spf_result = dns_auth.get("spf_status") or "none"
            if analysis.dmarc_result is None:
                analysis.dmarc_result = dns_auth.get("dmarc_status") or "none"
            if analysis.dkim_result is None:
                analysis.dkim_result = "none"
            if not analysis.authentication_results:
                analysis.authentication_results = {
                    "spf": analysis.spf_result,
                    "dkim": analysis.dkim_result,
                    "dmarc": analysis.dmarc_result,
                    "spf_record": dns_auth.get("spf_record"),
                    "dmarc_record": dns_auth.get("dmarc_record"),
                }
            await db.commit()
        except Exception as auth_err:
            logger.debug(f"Auth fallback lookup skipped for {analysis.id}: {auth_err}")

    # If email still lacks a threat score, evaluate on the fly
    if analysis.threat_score is None:
        try:
            from app.services.ai_service import get_ai_service, EmailThreatContext
            ai_svc = get_ai_service()
            context = EmailThreatContext(
                subject=analysis.subject or "",
                sender_email=analysis.sender_email or "",
                sender_domain=analysis.sender_domain or "",
                reply_to=analysis.reply_to,
                recipient_count=len(analysis.recipients or []),
                spf_result=analysis.spf_result,
                dkim_result=analysis.dkim_result,
                dmarc_result=analysis.dmarc_result,
                extracted_urls=[],
                extracted_ips=[],
                attachment_count=0,
                attachment_names=[],
                attachment_types=[],
                body_text_snippet=analysis.subject or "",
                threat_intel_summary={},
            )
            classification = await ai_svc.classify_threat(context)
            analysis.threat_category = classification.threat_category
            analysis.severity = classification.severity
            analysis.confidence_score = classification.confidence_score
            analysis.ai_reasoning = classification.reasoning
            analysis.ai_indicators = classification.indicators
            analysis.ai_model_used = classification.model_used

            # Dynamic authentication & threat evaluation
            if analysis.spf_result == "pass" and analysis.dkim_result == "pass" and analysis.dmarc_result == "pass":
                # Check for malicious IOC presence
                has_malicious_ioc = any(getattr(i, "is_malicious", False) for i in (analysis.iocs or []))
                if not has_malicious_ioc:
                    score = 0.0
                    analysis.severity = SeverityLevel.LOW
                else:
                    score = 35.0
                    analysis.severity = SeverityLevel.MEDIUM
            elif analysis.spf_result in ("fail", "softfail") or analysis.dmarc_result == "fail":
                score = 75.0
                analysis.severity = SeverityLevel.HIGH
            else:
                sev = str(analysis.severity).upper()
                if "CRITICAL" in sev:
                    score = 88.0
                elif "HIGH" in sev:
                    score = 72.0
                elif "MEDIUM" in sev:
                    score = 48.0
                else:
                    score = 12.0

            analysis.threat_score = score
            if analysis.status == AnalysisStatus.PENDING:
                analysis.status = AnalysisStatus.COMPLETE
            if not analysis.ai_summary:
                analysis.ai_summary = await ai_svc.generate_summary(context, classification)
            await db.commit()
            await db.refresh(analysis)
        except Exception as eval_err:
            logger.warning(f"Could not auto-evaluate threat score for {analysis.id}: {eval_err}")

    norm_geo = _normalize_analysis_geo_data(analysis.geo_data)
    if not norm_geo or not norm_geo.get("country") or not norm_geo.get("ip_address"):
        from app.services.geo_service import GeoService
        geo_svc = GeoService()
        obs_ips = _extract_observed_ips_from_analysis(analysis)
        target_ips = [i.ip_address for i in obs_ips if not i.is_private]
        if not target_ips and analysis.sender_domain:
            import socket
            try:
                dom_clean = analysis.sender_domain.strip().lower()
                if dom_clean and not dom_clean.endswith(".local") and not dom_clean.endswith(".lan"):
                    dom_ip = socket.gethostbyname(dom_clean)
                    if dom_ip:
                        target_ips.append(dom_ip)
            except Exception:
                pass
        if not target_ips:
            target_ips = ["1.1.1.1"]

        try:
            geo_res = await geo_svc.geolocate(target_ips[0], include_comparison=False)
            analysis.geo_data = {
                **(geo_res if isinstance(geo_res, dict) else {}),
                "ips": [geo_res] if isinstance(geo_res, dict) else [],
                "primary_ip": target_ips[0],
            }
            await db.commit()
            await db.refresh(analysis)
            norm_geo = _normalize_analysis_geo_data(analysis.geo_data)
        except Exception as g_err:
            logger.warning(f"On-the-fly geo lookup failed for {analysis.id}: {g_err}")

    primary_ip = norm_geo.get("ip_address") if norm_geo else None
    norm_enrich = _normalize_analysis_enrichment_data(analysis.enrichment_data, primary_ip)
    observed_ips = _extract_observed_ips_from_analysis(analysis)
    diagnostic_status = _build_diagnostic_status(analysis, norm_geo, norm_enrich, observed_ips)

    data = EmailAnalysisDetail.model_validate(analysis)
    data.geo_data = norm_geo
    data.enrichment_data = norm_enrich
    data.diagnostic_status = diagnostic_status

    # Normalize IOC items so none return is_malicious=None or threat_score=None
    if data.iocs:
        normalized_iocs = []
        for ioc in data.iocs:
            ioc_dict = ioc.model_dump()
            if ioc_dict.get("is_malicious") is None:
                ioc_dict["is_malicious"] = False
            if ioc_dict.get("threat_score") is None:
                ioc_dict["threat_score"] = 0
            normalized_iocs.append(ioc_dict)
        from app.schemas.email_analysis import IOCSchema
        data.iocs = [IOCSchema.model_validate(i) for i in normalized_iocs]

    return data



@router.get("/{analysis_id}/ips", response_model=EmailObservedIPsResponse)
async def get_analysis_observed_ips(
    analysis_id: uuid.UUID,
    db: DbSession,
    current_user: CurrentUser,
    member: Annotated[WorkspaceMember, Depends(require_workspace_role())],
    workspace_id: uuid.UUID | None = Query(None, description="Workspace the analysis belongs to"),
):
    """
    Retrieve all observed IP addresses for an email analysis with forensic provenance.
    Strictly scoped to the authorized workspace.
    """
    target_ws = workspace_id or (member.workspace_id if member else None)
    analysis = await _get_or_404(db, analysis_id, workspace_id=target_ws)

    # Ensure Gmail email has run pipeline if missing geo
    if (analysis.source_provider in ("google", "gmail")) and analysis.source_message_id and (analysis.geo_data is None or analysis.received_headers is None):
        try:
            from app.models.integrations import GmailConnection
            from app.services.gmail_service import gmail_service

            conn_res = await db.execute(
                select(GmailConnection).where(
                    GmailConnection.workspace_id == analysis.workspace_id,
                    GmailConnection.status == "ACTIVE",
                )
            )
            connection = conn_res.scalar_one_or_none()
            if not connection:
                conn_res = await db.execute(
                    select(GmailConnection).where(GmailConnection.workspace_id == analysis.workspace_id)
                )
                connection = conn_res.scalar_one_or_none()

            if connection:
                raw_bytes = await gmail_service.get_raw_message(db, connection, analysis.source_message_id)
                pipeline = ThreatAnalysisPipeline()
                await pipeline.run(db, analysis, raw_bytes)
                await db.commit()
                analysis = await _get_or_404(db, analysis_id, workspace_id=target_ws)
        except Exception as err:
            logger.warning(f"Could not auto-populate geo for Gmail email {analysis.id}: {err}")

    observed_ips = _extract_observed_ips_from_analysis(analysis)
    public_count = sum(1 for ip in observed_ips if not ip.is_private)

    return EmailObservedIPsResponse(
        analysis_id=analysis.id,
        ips=observed_ips,
        public_ips_count=public_count,
        total_ips_count=len(observed_ips),
    )


@router.get("/{analysis_id}/ip-trace", response_model=dict)
async def get_analysis_ip_trace(
    analysis_id: uuid.UUID,
    db: DbSession,
    current_user: CurrentUser,
    member: Annotated[WorkspaceMember, Depends(require_workspace_role())],
    workspace_id: uuid.UUID | None = Query(None, description="Workspace the analysis belongs to"),
):
    """
    Construct full multi-hop transit graph, NAT boundary detection, and
    evidence ledger for an email analysis.
    """
    from app.services.ip_trace.service import IPTraceService
    target_ws = workspace_id or (member.workspace_id if member else None)
    analysis = await _get_or_404(db, analysis_id, workspace_id=target_ws)

    tracer = IPTraceService()
    result = await tracer.trace_email_analysis(
        analysis=analysis,
        workspace_id=analysis.workspace_id,
        user_id=current_user.id,
    )
    return result


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

async def _get_or_404(
    db: DbSession,
    analysis_id: uuid.UUID,
    workspace_id: uuid.UUID | None = None,
) -> EmailAnalysis:
    """
    Fetch an EmailAnalysis by ID, optionally enforcing workspace ownership.

    When ``workspace_id`` is provided, the query includes a workspace filter
    so that a record from another workspace cannot be accessed even if its
    UUID is known (BOLA/IDOR prevention).
    """
    from sqlalchemy.orm import selectinload

    q = (
        select(EmailAnalysis)
        .where(EmailAnalysis.id == analysis_id)
        .options(
            selectinload(EmailAnalysis.iocs),
            selectinload(EmailAnalysis.attachments),
        )
    )
    if workspace_id is not None:
        q = q.where(EmailAnalysis.workspace_id == workspace_id)

    result = await db.execute(q)
    analysis = result.scalar_one_or_none()
    if analysis is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")
    return analysis


async def _run_analysis(analysis_id: uuid.UUID, raw_bytes: bytes) -> None:
    """Background task: run full threat analysis pipeline."""
    from app.db.session import AsyncSessionLocal
    for attempt in range(5):
        async with AsyncSessionLocal() as db:
            try:
                analysis = await db.get(EmailAnalysis, analysis_id)
                if analysis is None:
                    await asyncio.sleep(0.5)
                    continue
                logger.info("background_analysis_started", analysis_id=str(analysis_id))
                pipeline = ThreatAnalysisPipeline()
                await pipeline.run(db, analysis, raw_bytes)
                await db.commit()
                logger.info("background_analysis_completed", analysis_id=str(analysis_id), status=analysis.status.value)
                return
            except Exception as e:
                logger.error("background_analysis_error", analysis_id=str(analysis_id), error=str(e), exc_info=True)
                async with AsyncSessionLocal() as db2:
                    analysis = await db2.get(EmailAnalysis, analysis_id)
                    if analysis:
                        analysis.status = AnalysisStatus.FAILED
                        analysis.error_message = str(e)
                        await db2.commit()
                return
