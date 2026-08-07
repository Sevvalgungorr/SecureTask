"""Registered assets for monitoring

Monitoring means the server opens connections on a user's behalf, so a target
cannot arrive with the request. It is registered first, and a host may only be
registered once per owner.

Findings also gain source_severity: what the tool last rated a finding, kept
apart from what the row says now. Without it a re-run cannot tell "the evidence
got worse" from "a person disagreed with the tool".

Revision ID: a9e1f4b26c73
Revises: f7d3a5c81e02
Create Date: 2026-08-06 15:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a9e1f4b26c73'
down_revision: Union[str, Sequence[str], None] = 'f7d3a5c81e02'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'assets',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('label', sa.String(length=255), server_default='', nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('owner_id', 'host', name='uq_assets_owner_host'),
    )
    op.create_index(op.f('ix_assets_id'), 'assets', ['id'])
    op.create_index(op.f('ix_assets_owner_id'), 'assets', ['owner_id'])

    # Empty for hand-filed findings and for rows that predate any tool.
    op.add_column(
        'findings',
        sa.Column('source_severity', sa.String(length=10), nullable=False, server_default=''),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('findings', 'source_severity')
    op.drop_index(op.f('ix_assets_owner_id'), table_name='assets')
    op.drop_index(op.f('ix_assets_id'), table_name='assets')
    op.drop_table('assets')
