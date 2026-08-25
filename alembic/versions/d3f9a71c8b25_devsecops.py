"""CI/CD integrations and pipeline runs

Two tables and two columns.

`ci_integrations` is the machine credential and the repository mapping in one
row, because they are the same decision: this token, for this repository, files
into this tenant. The token itself is not here — only its SHA-256, which is
what verification needs and what a database dump must not contain.

`pipeline_runs` is the decision that follows from several scans together. Its
unique `(integration_id, external_run_id)` is what makes a retried CI request
idempotent: the constraint decides, rather than a check somebody has to
remember to write.

`scan_runs.pipeline_id` links the two, and `scan_runs.blocking` records how
many of a run's findings are critical and still open — counted at ingest time,
because "critical findings in this tenant" is a different and wrong question
for a gate to ask.

Revision ID: d3f9a71c8b25
Revises: b8e4f21d9a37
Create Date: 2026-08-25

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'd3f9a71c8b25'
down_revision: Union[str, Sequence[str], None] = 'b8e4f21d9a37'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'ci_integrations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('repository', sa.String(length=200), nullable=False),
        sa.Column('provider', sa.String(length=30), server_default='github', nullable=False),
        sa.Column('project', sa.String(length=80), server_default='', nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('label', sa.String(length=80), server_default='', nullable=False),
        sa.Column('dast_target', sa.String(length=80), server_default='', nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_ci_integrations_id', 'ci_integrations', ['id'])
    op.create_index('ix_ci_integrations_repository', 'ci_integrations', ['repository'], unique=True)
    # Verification is a lookup by hash, so this index is the mechanism and not
    # an optimisation: without it, checking a token would scan the table.
    op.create_index('ix_ci_integrations_token_hash', 'ci_integrations', ['token_hash'], unique=True)
    op.create_index('ix_ci_integrations_owner_id', 'ci_integrations', ['owner_id'])
    op.create_index('ix_ci_integrations_team_id', 'ci_integrations', ['team_id'])

    op.create_table(
        'pipeline_runs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('integration_id', sa.Integer(), nullable=False),
        sa.Column('repository', sa.String(length=200), nullable=False),
        sa.Column('provider', sa.String(length=30), server_default='github', nullable=False),
        sa.Column('branch', sa.String(length=200), server_default='', nullable=False),
        sa.Column('commit_sha', sa.String(length=64), server_default='', nullable=False),
        sa.Column('pull_request', sa.Integer(), nullable=True),
        sa.Column('external_run_id', sa.String(length=120), nullable=False),
        sa.Column('external_url', sa.String(length=500), server_default='', nullable=False),
        sa.Column('status', sa.String(length=20), server_default='running', nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('security_gate', sa.String(length=20), server_default='incomplete', nullable=False),
        sa.Column('gate_reason', sa.String(length=300), server_default='', nullable=False),
        sa.Column('environment', sa.String(length=30), server_default='', nullable=False),
        sa.Column('deployment_status', sa.String(length=20), server_default='', nullable=False),
        sa.Column('deployment_ref', sa.String(length=120), server_default='', nullable=False),
        sa.Column('deployed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('dast_status', sa.String(length=30), server_default='', nullable=False),
        sa.Column('release_status', sa.String(length=20), server_default='incomplete', nullable=False),
        sa.Column('release_reason', sa.String(length=300), server_default='', nullable=False),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['integration_id'], ['ci_integrations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('integration_id', 'external_run_id', name='uq_pipeline_run'),
    )
    op.create_index('ix_pipeline_runs_id', 'pipeline_runs', ['id'])
    op.create_index('ix_pipeline_runs_integration_id', 'pipeline_runs', ['integration_id'])
    op.create_index('ix_pipeline_runs_owner_id', 'pipeline_runs', ['owner_id'])
    op.create_index('ix_pipeline_runs_team_id', 'pipeline_runs', ['team_id'])

    op.add_column('scan_runs', sa.Column('blocking', sa.Integer(), server_default='0', nullable=False))
    op.add_column('scan_runs', sa.Column('pipeline_id', sa.Integer(), nullable=True))
    op.create_index('ix_scan_runs_pipeline_id', 'scan_runs', ['pipeline_id'])
    op.create_foreign_key(
        'fk_scan_runs_pipeline', 'scan_runs', 'pipeline_runs',
        ['pipeline_id'], ['id'], ondelete='CASCADE',
    )


def downgrade() -> None:
    op.drop_constraint('fk_scan_runs_pipeline', 'scan_runs', type_='foreignkey')
    op.drop_index('ix_scan_runs_pipeline_id', table_name='scan_runs')
    op.drop_column('scan_runs', 'pipeline_id')
    op.drop_column('scan_runs', 'blocking')
    op.drop_table('pipeline_runs')
    op.drop_table('ci_integrations')
