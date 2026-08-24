"""Runs of a local static analyser

A scan is an event with an outcome, not only a way of producing findings. The
findings stay ordinary findings; this records who ran what, over which
registered project, and whether it worked.

Revision ID: e1a7c93b48d2
Revises: d3f8b1a02e57
Create Date: 2026-08-20 14:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e1a7c93b48d2'
down_revision: Union[str, Sequence[str], None] = 'd3f8b1a02e57'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'scan_runs',
        sa.Column('id', sa.Integer(), nullable=False),
        # The registered name, never a path: a path stored here invites a later
        # feature to read it back out and use it.
        sa.Column('project', sa.String(length=80), nullable=False),
        sa.Column('scanner', sa.String(length=30), server_default='bandit', nullable=False),
        sa.Column('status', sa.String(length=20), server_default='queued', nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created', sa.Integer(), server_default='0', nullable=False),
        sa.Column('reopened', sa.Integer(), server_default='0', nullable=False),
        sa.Column('unchanged', sa.Integer(), server_default='0', nullable=False),
        sa.Column('total', sa.Integer(), server_default='0', nullable=False),
        sa.Column('error', sa.String(length=400), server_default='', nullable=False),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_scan_runs_id'), 'scan_runs', ['id'])
    op.create_index(op.f('ix_scan_runs_owner_id'), 'scan_runs', ['owner_id'])
    op.create_index(op.f('ix_scan_runs_team_id'), 'scan_runs', ['team_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_scan_runs_team_id'), table_name='scan_runs')
    op.drop_index(op.f('ix_scan_runs_owner_id'), table_name='scan_runs')
    op.drop_index(op.f('ix_scan_runs_id'), table_name='scan_runs')
    op.drop_table('scan_runs')
