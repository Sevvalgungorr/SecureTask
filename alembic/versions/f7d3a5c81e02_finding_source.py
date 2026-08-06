"""Record where a finding came from

A finding typed in by hand and one produced by a scanner are the same row, but
only the second can be matched against a later scan. `source` says which it is;
`source_ref` holds the scanner's own rule id, and the pair (owner, asset,
source_ref) is what makes a re-scan update rather than duplicate.

Revision ID: f7d3a5c81e02
Revises: e5b7c2d4a819
Create Date: 2026-08-05 14:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f7d3a5c81e02'
down_revision: Union[str, Sequence[str], None] = 'e5b7c2d4a819'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Existing rows were all typed in by hand, which is what the defaults say.
    op.add_column(
        'findings',
        sa.Column('source', sa.String(length=30), nullable=False, server_default='manual'),
    )
    op.add_column(
        'findings',
        sa.Column('source_ref', sa.String(length=255), nullable=False, server_default=''),
    )
    op.create_index(
        'ix_findings_dedupe', 'findings', ['owner_id', 'asset', 'source_ref'],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_findings_dedupe', table_name='findings')
    op.drop_column('findings', 'source_ref')
    op.drop_column('findings', 'source')
