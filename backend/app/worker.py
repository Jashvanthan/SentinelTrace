"""
SentinelTrace Backend — Celery Background Worker
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from celery import Celery
from celery.exceptions import Retry
from googleapiclient.errors import HttpError
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession

from app.core.config import get_settings
from app.models.integrations import GmailConnection
from app.models.jobs import GmailSyncJob, SyncJobStatus
from app.models.email_analysis import EmailAnalysis, AnalysisStatus
from app.services.gmail_service import gmail_service
from app.services.email_service import parse_eml
from app.services.neo4j_service import get_neo4j_service
from app.services.event_service import publish_workspace_event
from app.schemas.events import RealTimeEvent, RealTimeEventType

logger = logging.getLogger(__name__)
settings = get_settings()

celery_app = Celery(
    "sentineltrace_worker",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)
celery_app.conf.task_serializer = "json"

# Create a synchronous wrapper context for async DB tasks
engine = create_async_engine(settings.DATABASE_URL, future=True)
async_session_maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


def run_async(coro):
    """Run an async coroutine in the current thread's event loop."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


@celery_app.task(bind=True, max_retries=5)
def sync_gmail_account(self, job_id: str, workspace_id_str: str, connection_id_str: str) -> dict:
    """
    Background job to sync emails from a Gmail account.
    Validates workspace, decrypts tokens, pulls emails, parses with email_parser,
    geolocates IPs, and saves to Neo4j.
    """
    return run_async(_async_sync_gmail_account(self, job_id, workspace_id_str, connection_id_str))


async def _async_sync_gmail_account(task, job_id: str, workspace_id_str: str, connection_id_str: str) -> dict:
    import uuid
    workspace_id = uuid.UUID(workspace_id_str)
    connection_id = uuid.UUID(connection_id_str)
    
    neo4j = get_neo4j_service()

    async with async_session_maker() as db:
        # Load Job and Connection
        result = await db.execute(select(GmailSyncJob).where(GmailSyncJob.job_id == job_id))
        job = result.scalar_one_or_none()
        
        result = await db.execute(select(GmailConnection).where(GmailConnection.id == connection_id))
        connection = result.scalar_one_or_none()

        if not job or not connection:
            logger.error("Job or Connection not found")
            return {"error": "Missing entities"}
            
        if connection.workspace_id != workspace_id:
            logger.error("Security Violation: Workspace ID mismatch")
            job.status = SyncJobStatus.FAILED
            job.error_info = {"error": "Workspace mismatch"}
            await db.commit()
            return {"error": "Workspace mismatch"}

        job.status = SyncJobStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        await db.commit()

        # Always start fetching from the top of mailbox so new incoming messages are ingested
        page_token = None
        
        try:
            while True:
                # 1. Fetch List
                try:
                    response = await gmail_service.list_messages(db, connection, max_results=50, page_token=page_token)
                except HttpError as e:
                    if e.resp.status == 429:
                        # Exponential backoff
                        delay_seconds = 2 ** task.request.retries
                        logger.warning(f"Gmail Rate limit hit. Retrying in {delay_seconds} seconds...")
                        raise task.retry(exc=e, countdown=delay_seconds)
                    raise e
                    
                messages = response.get('messages', [])
                if not messages:
                    break
                    
                job.total += len(messages)
                await db.commit()

                # 2. Process each message
                for msg_ref in messages:
                    msg_id = msg_ref['id']
                    
                    # Check for duplicate
                    dup_check = await db.execute(
                        select(EmailAnalysis).where(
                            EmailAnalysis.workspace_id == workspace_id,
                            EmailAnalysis.source_provider == "google",
                            EmailAnalysis.source_message_id == msg_id
                        )
                    )
                    if dup_check.scalar_one_or_none():
                        job.processed += 1
                        continue # Already processed

                    try:
                        import hashlib
                        from email.utils import parsedate_to_datetime
                        from app.services.threat_service import ThreatAnalysisPipeline

                        pipeline_helper = ThreatAnalysisPipeline()
                        raw_bytes = None
                        try:
                            raw_bytes = await gmail_service.get_raw_message(db, connection, msg_id)
                        except Exception as raw_err:
                            logger.warning(f"Could not fetch raw MIME for Gmail msg {msg_id}: {raw_err}")

                        analysis_mode = (connection.analysis_mode or "AUTO").upper()

                        if raw_bytes and len(raw_bytes) > 0:
                            # Full raw RFC 5322 parsing
                            parsed = parse_eml(raw_bytes)
                            parsed_date = pipeline_helper._parse_email_date(parsed.email_date)

                            analysis = EmailAnalysis(
                                workspace_id=workspace_id,
                                analyst_id=connection.user_id,
                                source_provider="google",
                                source_message_id=msg_id,
                                subject=parsed.subject,
                                sender_email=parsed.sender_email,
                                sender_display_name=parsed.sender_display_name,
                                sender_domain=parsed.sender_domain,
                                reply_to=parsed.reply_to,
                                recipients=parsed.recipients,
                                message_id=parsed.message_id or msg_id,
                                email_date=parsed_date,
                                received_headers=parsed.received_headers,
                                all_headers=parsed.all_headers,
                                authentication_results=parsed.authentication_results,
                                spf_result=parsed.spf_result,
                                dkim_result=parsed.dkim_result,
                                dmarc_result=parsed.dmarc_result,
                                raw_eml_sha256=hashlib.sha256(raw_bytes).hexdigest(),
                                raw_eml_size_bytes=len(raw_bytes),
                                status=AnalysisStatus.PENDING,
                            )
                            db.add(analysis)
                            await db.commit()
                            await db.refresh(analysis)

                            if analysis_mode == "AUTO":
                                # Mode A: Automatically queue and execute full threat analysis pipeline
                                try:
                                    await pipeline_helper.run(db, analysis, raw_bytes)
                                except Exception as pipe_err:
                                    logger.error(f"Threat analysis failed on Gmail msg {msg_id}: {pipe_err}")
                            else:
                                # Mode B: Monitor & Review — Fetch metadata/content only, STOP without automatic AI/threat analysis
                                logger.info(f"Ingested Gmail msg {msg_id} in MANUAL mode (PENDING review)")
                        else:
                            # Fallback: metadata message format
                            from app.services.email_service import _parse_address, _decode_header_value

                            msg_data = await gmail_service.get_message(db, connection, msg_id)
                            payload = msg_data.get('payload', {})
                            headers_list = payload.get('headers', [])
                            headers_dict = {
                                str(h.get('name', '')).lower(): str(h.get('value', ''))
                                for h in headers_list if isinstance(h, dict)
                            }

                            from_raw = headers_dict.get('from', '')
                            sender_email, sender_display_name = _parse_address(from_raw)
                            sender_domain = sender_email.split('@')[-1] if sender_email and '@' in sender_email else None

                            to_raw = headers_dict.get('to', '')
                            recipients = [addr.strip() for addr in to_raw.split(',') if addr.strip()] if to_raw else []

                            subject_raw = headers_dict.get('subject') or msg_data.get('snippet') or '(No Subject)'
                            subject = _decode_header_value(subject_raw)

                            date_raw = headers_dict.get('date')
                            parsed_date = None
                            if date_raw:
                                try:
                                    parsed_date = parsedate_to_datetime(date_raw)
                                except Exception:
                                    parsed_date = None

                            msg_sha256 = hashlib.sha256(f"{msg_id}_{subject}_{from_raw}_{to_raw}_{date_raw}".encode()).hexdigest()

                            analysis = EmailAnalysis(
                                workspace_id=workspace_id,
                                analyst_id=connection.user_id,
                                source_provider="google",
                                source_message_id=msg_id,
                                subject=subject,
                                sender_email=sender_email or None,
                                sender_display_name=sender_display_name or None,
                                sender_domain=sender_domain,
                                recipients=recipients,
                                reply_to=headers_dict.get('reply-to'),
                                message_id=headers_dict.get('message-id', msg_id),
                                email_date=parsed_date,
                                raw_eml_sha256=msg_sha256,
                                status=AnalysisStatus.COMPLETE if analysis_mode == "AUTO" else AnalysisStatus.PENDING,
                                threat_score=0.0 if analysis_mode == "AUTO" else None,
                            )
                            db.add(analysis)
                            await db.commit()

                        job.processed += 1

                        # Publish SSE Event that email is synced and ready on the dashboard
                        event = RealTimeEvent(
                            event_type=RealTimeEventType.ANALYSIS_COMPLETED if analysis.status == AnalysisStatus.COMPLETE else RealTimeEventType.EMAIL_RECEIVED,
                            workspace_id=workspace_id,
                            title="Gmail Ingested" if analysis_mode == "MANUAL" else "Gmail Analyzed",
                            message=f"Synced: {analysis.subject or '(No Subject)'}",
                            resource_type="email_analysis",
                            resource_id=str(analysis.id)
                        )
                        await publish_workspace_event(workspace_id, event)

                    except Exception as e:
                        logger.error(f"Failed to ingest Gmail message {msg_id}: {e}")
                        await db.rollback()
                        job.failed += 1

                # 3. Handle Pagination
                page_token = response.get('nextPageToken')
                connection.last_sync_cursor = page_token
                await db.commit()
                
                if not page_token:
                    break

            # Finish Job
            job.status = SyncJobStatus.PARTIAL if job.failed > 0 else SyncJobStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc)
            connection.last_sync_at = datetime.now(timezone.utc)
            await db.commit()
            
            return {"status": job.status, "processed": job.processed, "failed": job.failed}

        except Exception as e:
            logger.error(f"Job failed: {e}")
            job.status = SyncJobStatus.FAILED
            job.error_info = {"error": str(e)}
            job.completed_at = datetime.now(timezone.utc)
            await db.commit()
            return {"error": str(e)}

@celery_app.task(bind=True, max_retries=3)
def triage_email_with_agents(self, workspace_id_str: str, email_analysis_id_str: str) -> dict:
    """
    Background job to run the AI agent triage pipeline for a specific email.
    """
    return run_async(_async_triage_email(self, workspace_id_str, email_analysis_id_str))

async def _async_triage_email(task, workspace_id_str: str, email_analysis_id_str: str) -> dict:
    import uuid
    from app.services.agent_orchestrator import AgentOrchestrator
    
    workspace_id = uuid.UUID(workspace_id_str)
    email_analysis_id = uuid.UUID(email_analysis_id_str)
    
    # Generate idempotency key for this run using Celery task ID (persists across retries)
    analysis_run_id = task.request.id or str(uuid.uuid4())
    
    orchestrator = AgentOrchestrator()
    
    async with async_session_maker() as db:
        try:
            result = await orchestrator.orchestrate(db, workspace_id, email_analysis_id, analysis_run_id)
            return result
        except Exception as e:
            logger.error(f"Orchestration failed for email {email_analysis_id}: {e}")
            return {
                "workspace_id": workspace_id_str,
                "email_analysis_id": email_analysis_id_str,
                "analysis_run_id": analysis_run_id,
                "status": "FAILED",
                "error": str(e)
            }


@celery_app.task(bind=True, max_retries=3)
def analyze_uploaded_eml(self, workspace_id_str: str, analysis_id_str: str, raw_eml_bytes_hex: str) -> dict:
    """
    Background job to execute the threat analysis pipeline for an uploaded EML file.
    Runs enrichments, geo, AI classification/LLM, Neo4j, risk scoring, and persists results.
    """
    return run_async(_async_analyze_uploaded_eml(self, workspace_id_str, analysis_id_str, raw_eml_bytes_hex))


async def _async_analyze_uploaded_eml(task, workspace_id_str: str, analysis_id_str: str, raw_eml_bytes_hex: str) -> dict:
    import uuid
    from app.services.threat_service import ThreatAnalysisPipeline
    from app.services.audit_service import write_audit_log

    workspace_id = uuid.UUID(workspace_id_str)
    analysis_id = uuid.UUID(analysis_id_str)
    raw_eml_bytes = bytes.fromhex(raw_eml_bytes_hex)

    async with async_session_maker() as db:
        result = await db.execute(
            select(EmailAnalysis).where(
                EmailAnalysis.id == analysis_id,
                EmailAnalysis.workspace_id == workspace_id,
            )
        )
        analysis = result.scalar_one_or_none()
        if not analysis:
            logger.error(f"EmailAnalysis {analysis_id} not found in workspace {workspace_id}")
            return {"status": "FAILED", "error": "Analysis not found"}

        analysis.status = AnalysisStatus.PROCESSING
        await db.commit()

        pipeline = ThreatAnalysisPipeline()
        try:
            await pipeline.run(db, analysis, raw_eml_bytes)
            await write_audit_log(
                db,
                action="EMAIL_FORENSIC_ANALYSIS_COMPLETED",
                user_id=analysis.analyst_id,
                resource_type="email_analysis",
                resource_id=str(analysis.id),
                details={
                    "subject": analysis.subject,
                    "threat_category": str(analysis.threat_category.value if hasattr(analysis.threat_category, "value") else analysis.threat_category),
                    "severity": str(analysis.severity.value if hasattr(analysis.severity, "value") else analysis.severity),
                    "threat_score": analysis.threat_score,
                },
                outcome="SUCCESS" if analysis.status == AnalysisStatus.COMPLETE else "FAILURE",
            )
            await db.commit()

            # Publish SSE real-time event
            event = RealTimeEvent(
                event_type=RealTimeEventType.ANALYSIS_COMPLETED,
                workspace_id=workspace_id,
                title="Analysis Complete",
                message=f"Forensic analysis completed for: {analysis.subject or '(No Subject)'}",
                severity=str(analysis.severity.value if hasattr(analysis.severity, 'value') else analysis.severity) if analysis.severity else "INFO",
                resource_type="email_analysis",
                resource_id=str(analysis.id),
            )
            await publish_workspace_event(workspace_id, event)

            return {
                "workspace_id": workspace_id_str,
                "analysis_id": analysis_id_str,
                "status": analysis.status.value if hasattr(analysis.status, "value") else str(analysis.status),
                "threat_score": analysis.threat_score,
            }
        except Exception as e:
            logger.error(f"Analysis pipeline failed for {analysis_id}: {e}", exc_info=True)
            analysis.status = AnalysisStatus.FAILED
            analysis.error_message = str(e)
            await write_audit_log(
                db,
                action="EMAIL_FORENSIC_ANALYSIS_FAILED",
                user_id=analysis.analyst_id,
                resource_type="email_analysis",
                resource_id=str(analysis.id),
                details={"error": str(e)},
                outcome="FAILURE",
                error_message=str(e),
            )
            await db.commit()

            # Publish SSE real-time error event
            event = RealTimeEvent(
                event_type=RealTimeEventType.ANALYSIS_FAILED,
                workspace_id=workspace_id,
                title="Analysis Failed",
                message=f"Forensic analysis failed for: {analysis.subject or '(No Subject)'}",
                severity="HIGH",
                resource_type="email_analysis",
                resource_id=str(analysis.id),
            )
            await publish_workspace_event(workspace_id, event)

            return {
                "workspace_id": workspace_id_str,
                "analysis_id": analysis_id_str,
                "status": "FAILED",
                "error": str(e),
            }


@celery_app.task(bind=True, max_retries=3)
def analyze_email_job(self, workspace_id_str: str, analysis_id_str: str) -> dict:
    """
    Background job to execute full forensic threat analysis for an existing email analysis record.
    Used for manual review on-demand analysis.
    """
    return run_async(_async_analyze_email_job(self, workspace_id_str, analysis_id_str))


async def _async_analyze_email_job(task, workspace_id_str: str, analysis_id_str: str) -> dict:
    import uuid
    from app.services.threat_service import ThreatAnalysisPipeline
    from app.services.audit_service import write_audit_log

    workspace_id = uuid.UUID(workspace_id_str)
    analysis_id = uuid.UUID(analysis_id_str)

    async with async_session_maker() as db:
        result = await db.execute(
            select(EmailAnalysis).where(
                EmailAnalysis.id == analysis_id,
                EmailAnalysis.workspace_id == workspace_id,
            )
        )
        analysis = result.scalar_one_or_none()
        if not analysis:
            logger.error(f"EmailAnalysis {analysis_id} not found in workspace {workspace_id}")
            return {"status": "FAILED", "error": "Analysis not found"}

        if analysis.status == AnalysisStatus.COMPLETE and analysis.threat_score is not None:
            logger.info(f"EmailAnalysis {analysis_id} is already COMPLETE, skipping duplicate analysis.")
            return {"status": "COMPLETE", "analysis_id": analysis_id_str}

        analysis.status = AnalysisStatus.PROCESSING
        await db.commit()

        # Publish SSE real-time event: started
        event = RealTimeEvent(
            event_type=RealTimeEventType.ANALYSIS_STARTED,
            workspace_id=workspace_id,
            title="Analysis Started",
            message=f"Forensic threat analysis initiated for: {analysis.subject or '(No Subject)'}",
            resource_type="email_analysis",
            resource_id=str(analysis.id),
        )
        await publish_workspace_event(workspace_id, event)

        pipeline = ThreatAnalysisPipeline()
        try:
            raw_bytes = None
            if analysis.source_provider in ("google", "gmail") and analysis.source_message_id:
                conn_res = await db.execute(
                    select(GmailConnection).where(
                        GmailConnection.workspace_id == workspace_id,
                        GmailConnection.status == "ACTIVE",
                    )
                )
                connection = conn_res.scalar_one_or_none()
                if not connection:
                    conn_res = await db.execute(
                        select(GmailConnection).where(GmailConnection.workspace_id == workspace_id)
                    )
                    connection = conn_res.scalar_one_or_none()

                if connection:
                    try:
                        raw_bytes = await gmail_service.get_raw_message(db, connection, analysis.source_message_id)
                    except Exception as raw_e:
                        logger.warning(f"Could not retrieve raw MIME from Gmail: {raw_e}")

            if not raw_bytes or len(raw_bytes) == 0:
                # Synthesize standard EML bytes from stored headers/subject/body
                headers_lines = []
                if analysis.subject:
                    headers_lines.append(f"Subject: {analysis.subject}")
                if analysis.sender_email:
                    headers_lines.append(f"From: {analysis.sender_email}")
                if analysis.recipients:
                    headers_lines.append(f"To: {', '.join(analysis.recipients)}")
                if analysis.message_id:
                    headers_lines.append(f"Message-ID: <{analysis.message_id}>")
                if analysis.received_headers:
                    for h in analysis.received_headers:
                        headers_lines.append(f"Received: {h}")
                eml_text = "\r\n".join(headers_lines) + "\r\n\r\n" + (analysis.subject or "Email content")
                raw_bytes = eml_text.encode("utf-8")

            await pipeline.run(db, analysis, raw_bytes)
            await write_audit_log(
                db,
                action="EMAIL_FORENSIC_ANALYSIS_COMPLETED",
                user_id=analysis.analyst_id,
                resource_type="email_analysis",
                resource_id=str(analysis.id),
                details={
                    "subject": analysis.subject,
                    "threat_category": str(analysis.threat_category.value if hasattr(analysis.threat_category, "value") else analysis.threat_category),
                    "severity": str(analysis.severity.value if hasattr(analysis.severity, "value") else analysis.severity),
                    "threat_score": analysis.threat_score,
                },
                outcome="SUCCESS" if analysis.status == AnalysisStatus.COMPLETE else "FAILURE",
            )
            await db.commit()

            # Publish SSE real-time event: complete
            event = RealTimeEvent(
                event_type=RealTimeEventType.ANALYSIS_COMPLETED,
                workspace_id=workspace_id,
                title="Analysis Complete",
                message=f"Forensic analysis completed for: {analysis.subject or '(No Subject)'}",
                severity=str(analysis.severity.value if hasattr(analysis.severity, 'value') else analysis.severity) if analysis.severity else "INFO",
                resource_type="email_analysis",
                resource_id=str(analysis.id),
            )
            await publish_workspace_event(workspace_id, event)

            return {
                "workspace_id": workspace_id_str,
                "analysis_id": analysis_id_str,
                "status": analysis.status.value if hasattr(analysis.status, "value") else str(analysis.status),
                "threat_score": analysis.threat_score,
            }
        except Exception as e:
            logger.error(f"Manual analysis pipeline failed for {analysis_id}: {e}", exc_info=True)
            analysis.status = AnalysisStatus.FAILED
            analysis.error_message = str(e)
            await write_audit_log(
                db,
                action="EMAIL_FORENSIC_ANALYSIS_FAILED",
                user_id=analysis.analyst_id,
                resource_type="email_analysis",
                resource_id=str(analysis.id),
                details={"error": str(e)},
                outcome="FAILURE",
                error_message=str(e),
            )
            await db.commit()

            # Publish SSE real-time error event
            event = RealTimeEvent(
                event_type=RealTimeEventType.ANALYSIS_FAILED,
                workspace_id=workspace_id,
                title="Analysis Failed",
                message=f"Forensic analysis failed for: {analysis.subject or '(No Subject)'}",
                severity="HIGH",
                resource_type="email_analysis",
                resource_id=str(analysis.id),
            )
            await publish_workspace_event(workspace_id, event)

            return {
                "workspace_id": workspace_id_str,
                "analysis_id": analysis_id_str,
                "status": "FAILED",
                "error": str(e),
            }
