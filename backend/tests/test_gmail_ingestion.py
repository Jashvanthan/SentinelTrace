import pytest
from unittest.mock import MagicMock
from app.models.jobs import GmailSyncJob, SyncJobStatus

def test_sync_job_status_initialization():
    job = GmailSyncJob(
        job_id="test-job",
        workspace_id="00000000-0000-0000-0000-000000000000",
        gmail_connection_id="00000000-0000-0000-0000-000000000000",
        status=SyncJobStatus.QUEUED,
        total=0,
        processed=0,
        failed=0
    )
    assert job.status == SyncJobStatus.QUEUED
    assert job.total == 0
    assert job.processed == 0
    assert job.failed == 0
