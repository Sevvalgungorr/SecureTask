"""Risk acceptance register and an append-only audit chain

An accepted risk needs an argument, an owner and an end: without those it is
not a decision, it is a way of closing a ticket. And a log an administrator can
edit is not evidence of anything, so each entry now hashes itself together with
the previous entry's hash.

Revision ID: b4c8e2f19d05
Revises: a9e1f4b26c73
Create Date: 2026-08-07 09:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b4c8e2f19d05'
down_revision: Union[str, Sequence[str], None] = 'a9e1f4b26c73'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('findings', sa.Column('accepted_reason', sa.String(length=2000), nullable=True))
    op.add_column('findings', sa.Column('accepted_until', sa.Date(), nullable=True))
    op.add_column('findings', sa.Column('accepted_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('findings', sa.Column('accepted_by_id', sa.Integer(), nullable=True))
    op.create_foreign_key(
        'fk_findings_accepted_by', 'findings', 'users', ['accepted_by_id'], ['id'],
        ondelete='SET NULL',
    )

    # Existing entries carry no hash. They are not back-filled: signing them now
    # would assert they are unmodified, which nothing here can know. The
    # verification walk reports them as unchained rather than as valid.
    op.add_column(
        'audit_logs',
        sa.Column('prev_hash', sa.String(length=64), nullable=False, server_default=''),
    )
    op.add_column(
        'audit_logs',
        sa.Column('entry_hash', sa.String(length=64), nullable=False, server_default=''),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('audit_logs', 'entry_hash')
    op.drop_column('audit_logs', 'prev_hash')
    op.drop_constraint('fk_findings_accepted_by', 'findings', type_='foreignkey')
    op.drop_column('findings', 'accepted_by_id')
    op.drop_column('findings', 'accepted_at')
    op.drop_column('findings', 'accepted_until')
    op.drop_column('findings', 'accepted_reason')
