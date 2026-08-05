"""Turn tasks into security findings

Renames the table and its risk-carrying columns instead of dropping and
recreating them, so existing rows survive: priority becomes severity, the
completed flag becomes a four-state status, and every finding gains the asset
it was observed on.

Revision ID: e5b7c2d4a819
Revises: c3a9f1e28b57
Create Date: 2026-08-05 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e5b7c2d4a819'
down_revision: Union[str, Sequence[str], None] = 'c3a9f1e28b57'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.rename_table('tasks', 'findings')
    op.alter_column('findings', 'priority', new_column_name='severity')

    # Postgres keeps the old index names through a table rename; line them up
    # with what create_all() would produce on a fresh database.
    op.execute('ALTER INDEX IF EXISTS ix_tasks_id RENAME TO ix_findings_id')
    op.execute('ALTER INDEX IF EXISTS ix_tasks_owner_id RENAME TO ix_findings_owner_id')

    op.add_column(
        'findings',
        sa.Column('asset', sa.String(length=255), nullable=False, server_default=''),
    )
    op.add_column(
        'findings',
        sa.Column('status', sa.String(length=20), nullable=False, server_default='open'),
    )

    # A completed task was work that is done, which maps to a fixed finding.
    # Accepted risk has no equivalent in the old model, so nothing backfills to it.
    op.execute("UPDATE findings SET status = 'fixed' WHERE completed IS TRUE")
    op.drop_column('findings', 'completed')

    op.alter_column('audit_logs', 'task_id', new_column_name='finding_id')
    op.execute('ALTER INDEX IF EXISTS ix_audit_logs_task_id RENAME TO ix_audit_logs_finding_id')


def downgrade() -> None:
    """Downgrade schema."""
    op.execute('ALTER INDEX IF EXISTS ix_audit_logs_finding_id RENAME TO ix_audit_logs_task_id')
    op.alter_column('audit_logs', 'finding_id', new_column_name='task_id')

    op.add_column(
        'findings',
        sa.Column('completed', sa.Boolean(), nullable=True, server_default=sa.false()),
    )
    # Both closed states collapse back to "completed" — the distinction between
    # a fixed finding and an accepted risk cannot survive a boolean.
    op.execute("UPDATE findings SET completed = TRUE WHERE status IN ('fixed', 'accepted_risk')")

    op.drop_column('findings', 'status')
    op.drop_column('findings', 'asset')
    op.alter_column('findings', 'severity', new_column_name='priority')
    op.execute('ALTER INDEX IF EXISTS ix_findings_owner_id RENAME TO ix_tasks_owner_id')
    op.execute('ALTER INDEX IF EXISTS ix_findings_id RENAME TO ix_tasks_id')
    op.rename_table('findings', 'tasks')
