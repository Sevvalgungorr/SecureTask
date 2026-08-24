"""How many findings a scan closed by no longer reporting them

Revision ID: f4b2d81c6a09
Revises: e1a7c93b48d2
Create Date: 2026-08-24 08:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f4b2d81c6a09'
down_revision: Union[str, Sequence[str], None] = 'e1a7c93b48d2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('scan_runs', sa.Column('resolved', sa.Integer(), server_default='0', nullable=False))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('scan_runs', 'resolved')
