"""Keep the lines a code scanner was looking at

A code finding says "line 42 of this file". Without the line itself that is a
reference to something the reader has to go and find; with it, the finding can
be judged where it sits. SARIF reports already carry the snippet, so this
stores what the report brought rather than fetching anything.

Revision ID: c8b1e6f04a37
Revises: d7f3a1c95e42
Create Date: 2026-08-18 09:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c8b1e6f04a37'
down_revision: Union[str, Sequence[str], None] = 'd7f3a1c95e42'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Capped rather than unbounded text: a snippet is context for one finding,
    # not a place to put a file.
    op.add_column('findings', sa.Column('evidence', sa.String(length=4000), nullable=True))
    # The first line of the block, and which line inside it the rule fired on.
    op.add_column('findings', sa.Column('evidence_start', sa.Integer(), nullable=True))
    op.add_column('findings', sa.Column('evidence_line', sa.Integer(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('findings', 'evidence_line')
    op.drop_column('findings', 'evidence_start')
    op.drop_column('findings', 'evidence')
