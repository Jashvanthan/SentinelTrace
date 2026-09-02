"""phase_4_ai_campaign

Revision ID: 7e6f289095d4
Revises: 539c7007dbf1
Create Date: 2026-09-02 13:35:24.451129
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = '7e6f289095d4'
down_revision: Union[str, None] = '539c7007dbf1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    risk_verdict_enum = sa.Enum('BENIGN', 'SUSPICIOUS', 'MEDIUM_RISK', 'HIGH_RISK', 'CRITICAL', name='risk_verdict_enum')
    agent_status_enum = sa.Enum('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'TIMEOUT', name='agent_status_enum')
    campaign_status_enum = sa.Enum('ACTIVE', 'MONITORING', 'MITIGATED', 'FALSE_POSITIVE', 'CLOSED', name='campaign_status_enum')
    threat_category_enum = sa.Enum('PHISHING', 'SPEAR_PHISHING', 'BEC', 'MALWARE', 'SPAM', 'RANSOMWARE', 'CREDENTIAL_HARVEST', 'SOCIAL_ENGINEERING', 'UNKNOWN', 'BENIGN', name='threat_category_enum')

    op.create_table(
        'ai_analyses',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('email_analysis_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('analysis_run_id', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('final_score', sa.Integer(), nullable=True),
        sa.Column('final_verdict', risk_verdict_enum, nullable=True),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('explanation', sa.Text(), nullable=True),
        sa.Column('key_findings', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('contributing_agents', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('conflicting_agents', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('deterministic_indicators', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['email_analysis_id'], ['email_analyses.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['workspace_id'], ['workspaces.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('workspace_id', 'analysis_run_id', name='uq_ai_analysis_run')
    )
    op.create_index('ix_ai_analysis_workspace_id', 'ai_analyses', ['workspace_id'], unique=False)
    op.create_index('ix_ai_analysis_email_id', 'ai_analyses', ['email_analysis_id'], unique=False)
    op.create_index('ix_ai_analysis_run_id', 'ai_analyses', ['analysis_run_id'], unique=False)

    op.create_table(
        'agent_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('ai_analysis_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('email_analysis_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('analysis_run_id', sa.String(), nullable=False),
        sa.Column('agent_name', sa.String(), nullable=False),
        sa.Column('agent_version', sa.String(), nullable=False),
        sa.Column('prompt_version', sa.String(), nullable=False),
        sa.Column('model', sa.String(), nullable=False),
        sa.Column('status', agent_status_enum, nullable=False),
        sa.Column('risk_score', sa.Integer(), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('classification', threat_category_enum, nullable=True),
        sa.Column('findings', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('recommendations', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('metadata_json', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('error_code', sa.String(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['ai_analysis_id'], ['ai_analyses.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['email_analysis_id'], ['email_analyses.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['workspace_id'], ['workspaces.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('workspace_id', 'analysis_run_id', 'agent_name', name='uq_agent_result_run_name')
    )
    op.create_index('ix_agent_result_workspace_id', 'agent_results', ['workspace_id'], unique=False)
    op.create_index('ix_agent_result_analysis_run_id', 'agent_results', ['analysis_run_id'], unique=False)
    op.create_index('ix_agent_result_ai_analysis_id', 'agent_results', ['ai_analysis_id'], unique=False)

    op.create_table(
        'campaigns',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', campaign_status_enum, nullable=False),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('correlation_score', sa.Integer(), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['workspace_id'], ['workspaces.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_campaign_workspace_id', 'campaigns', ['workspace_id'], unique=False)
    op.create_index('ix_campaign_workspace_status', 'campaigns', ['workspace_id', 'status'], unique=False)
    op.create_index('ix_campaign_workspace_last_seen', 'campaigns', ['workspace_id', 'last_seen_at'], unique=False)

    op.create_table(
        'campaign_members',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('workspace_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('campaign_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('email_analysis_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('correlation_score', sa.Integer(), nullable=True),
        sa.Column('correlation_confidence', sa.Float(), nullable=True),
        sa.Column('matched_indicators', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('correlation_reasons', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(['campaign_id'], ['campaigns.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['email_analysis_id'], ['email_analyses.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['workspace_id'], ['workspaces.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('workspace_id', 'campaign_id', 'email_analysis_id', name='uq_campaign_member')
    )
    op.create_index('ix_campaign_member_workspace_id', 'campaign_members', ['workspace_id'], unique=False)
    op.create_index('ix_campaign_member_campaign_id', 'campaign_members', ['campaign_id'], unique=False)
    op.create_index('ix_campaign_member_email_id', 'campaign_members', ['email_analysis_id'], unique=False)


def downgrade() -> None:
    op.drop_table('campaign_members')
    op.drop_table('campaigns')
    op.drop_table('agent_results')
    op.drop_table('ai_analyses')
    op.execute("DROP TYPE IF EXISTS threat_category_enum")
    op.execute("DROP TYPE IF EXISTS campaign_status_enum")
    op.execute("DROP TYPE IF EXISTS agent_status_enum")
    op.execute("DROP TYPE IF EXISTS risk_verdict_enum")
