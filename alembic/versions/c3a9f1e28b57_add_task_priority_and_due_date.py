"""Add task priority and due_date

Revision ID: c3a9f1e28b57
Revises: b2f8d5c19e34
Create Date: 2026-07-21 10:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3a9f1e28b57'
down_revision: Union[str, Sequence[str], None] = 'b2f8d5c19e34'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # server_default backfills existing rows with 'medium'.
    op.add_column(
        'tasks',
        sa.Column('priority', sa.String(length=10), nullable=False, server_default='medium'),
    )
    op.add_column('tasks', sa.Column('due_date', sa.Date(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('tasks', 'due_date')
    op.drop_column('tasks', 'priority')
