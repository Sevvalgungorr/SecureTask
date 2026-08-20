"""Which reference passages an analysis was given

Identifiers, not text. The passages live in app/knowledge/ so that correcting
one corrects every analysis that cited it; storing the prose here would freeze
whatever was true on the day the analysis ran.

Revision ID: d3f8b1a02e57
Revises: a7c3f19d5b84
Create Date: 2026-08-20 09:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd3f8b1a02e57'
down_revision: Union[str, Sequence[str], None] = 'a7c3f19d5b84'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('ai_analyses', sa.Column('sources', sa.String(length=500), server_default='', nullable=False))
    # Empty on every existing row, which is correct: they were produced before
    # there was a knowledge base, and that is exactly what empty records.
    op.add_column('ai_analyses', sa.Column('kb_version', sa.String(length=30), server_default='', nullable=False))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('ai_analyses', 'kb_version')
    op.drop_column('ai_analyses', 'sources')
