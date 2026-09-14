"""google_pending_nonces

Adds google_pending_nonces table for single-use Google registration tokens.

Revision ID: a1b2c3d4e5f6
Revises: ed01581368ef
Create Date: 2026-09-14 09:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = '7e6f289095d4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'google_pending_nonces',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('nonce', sa.String(length=128), nullable=False),
        sa.Column('google_sub', sa.String(length=256), nullable=False),
        sa.Column('email', sa.String(length=320), nullable=False),
        sa.Column('full_name', sa.String(length=256), nullable=False),
        sa.Column('picture', sa.String(length=2048), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('consumed', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('nonce', name='uq_google_pending_nonce'),
    )
    op.create_index(
        op.f('ix_google_pending_nonces_nonce'),
        'google_pending_nonces',
        ['nonce'],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_google_pending_nonces_nonce'), table_name='google_pending_nonces')
    op.drop_table('google_pending_nonces')
