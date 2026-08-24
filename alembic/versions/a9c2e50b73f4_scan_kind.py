"""Static or dynamic: which kind of scan a run was

One table for both. A run is a run — who started it, over what, with what
outcome; the kind changes what the row means, not how it is stored.

Revision ID: a9c2e50b73f4
Revises: f4b2d81c6a09
Create Date: 2026-08-24 11:05:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a9c2e50b73f4'
down_revision: Union[str, Sequence[str], None] = 'f4b2d81c6a09'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Existing rows are all static analysis, which is what the default records.
    op.add_column('scan_runs', sa.Column('kind', sa.String(length=10), server_default='sast', nullable=False))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('scan_runs', 'kind')
