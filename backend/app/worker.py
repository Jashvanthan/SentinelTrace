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
    loop = asyncio.get_event_loop()
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

        page_token = connection.last_sync_cursor
        
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
                        
                    # Fetch Raw
                    try:
                        raw_bytes = await gmail_service.get_raw_message(db, connection, msg_id)
                    except HttpError as e:
                        if e.resp.status == 429:
                            delay_seconds = 2 ** task.request.retries
                            raise task.retry(exc=e, countdown=delay_seconds)
                        logger.error(f"Failed to fetch message {msg_id}: {e}")
                        job.failed += 1
                        continue
                        
                    # Parse EML
                    try:
                        parsed = parse_eml(raw_bytes)
                        
                        analysis = EmailAnalysis(
                            workspace_id=workspace_id,
                            subject=parsed.subject,
                            sender_email=parsed.sender_email,
                            sender_display_name=parsed.sender_display_name,
                            sender_domain=parsed.sender_domain,
                            reply_to=parsed.reply_to,
                            recipients=parsed.recipients,
                            message_id=parsed.message_id,  # SMTP ID
                            source_provider="google",
                            source_message_id=msg_id,      # Gmail internal ID
                            status=AnalysisStatus.COMPLETE,
                            raw_eml_size_bytes=len(raw_bytes),
                            spf_result=parsed.spf_result,
                            dkim_result=parsed.dkim_result,
                            dmarc_result=parsed.dmarc_result,
                        )
                        db.add(analysis)
                        await db.commit()
                        
                        # Graph Correlation
                        await neo4j.upsert_email_analysis(
                            workspace_id=str(workspace_id),
                            analysis_id=str(analysis.id),
                            sender_email=parsed.sender_email,
                            sender_domain=parsed.sender_domain,
                            subject=parsed.subject,
                            threat_category=None,
                            severity=None,
                            iocs=[],  # IOC extraction comes next in the pipeline
                            received_ips=parsed.extracted_ips
                        )
                        
                        job.processed += 1
                    except Exception as e:
                        logger.error(f"Failed to process message {msg_id}: {e}")
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
