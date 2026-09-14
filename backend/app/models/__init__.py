"""
SentinelTrace Backend — Models Package

Import all models here so Alembic can discover them for autogenerate.
"""
from app.models.audit_log import AuditLog
from app.models.email_analysis import EmailAnalysis, EmailAttachment
from app.models.ioc import IOC
from app.models.refresh_session import RefreshSession
from app.models.threat_record import ThreatRecord
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMember
from app.models.integrations import GmailConnection
from app.models.oauth import ExternalIdentity, OAuthState
from app.models.google_pending import GooglePendingNonce
from app.models.jobs import GmailSyncJob
from app.models.ai_analysis import AIAnalysis, AgentResult
from app.models.campaign import Campaign, CampaignMember
from app.models.investigation import (
    Investigation,
    InvestigationEntity,
    AnalystNote,
    AnalystFinding,
    EvidenceVerification,
    InvestigationStatus,
    FindingSeverity,
    FindingConfidence,
    VerificationStatus,
)
from app.models.report import ForensicReport, ReportStatus

__all__ = [
    "User",
    "RefreshSession",
    "EmailAnalysis",
    "EmailAttachment",
    "IOC",
    "ThreatRecord",
    "AuditLog",
    "Workspace",
    "WorkspaceMember",
    "GmailConnection",
    "ExternalIdentity",
    "OAuthState",
    "GmailSyncJob",
    "AIAnalysis",
    "AgentResult",
    "Campaign",
    "CampaignMember",
]
