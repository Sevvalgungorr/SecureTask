"""Where a model's reading of a finding is kept

Deliberately its own table. These fields are an opinion *about* a finding, not
part of it; on the findings row they would read as the application's own rating,
and the first thing anyone would do is sort by risk_score as though something
had been decided.

Revision ID: a7c3f19d5b84
Revises: b4e9a2f76c15
Create Date: 2026-08-19 10:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7c3f19d5b84'
down_revision: Union[str, Sequence[str], None] = 'b4e9a2f76c15'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'ai_analyses',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('finding_id', sa.Integer(), nullable=False),
        sa.Column(
            'created_at', sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.Column('provider', sa.String(length=30), server_default='', nullable=False),
        sa.Column('model', sa.String(length=120), server_default='', nullable=False),
        sa.Column('code_sent', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('who_id', sa.Integer(), nullable=True),
        sa.Column('risk_score', sa.Numeric(precision=4, scale=1), server_default='0', nullable=False),
        sa.Column('suggested_severity', sa.String(length=10), server_default='medium', nullable=False),
        sa.Column('suggested_sla_hours', sa.Integer(), nullable=True),
        sa.Column('exploitability', sa.String(length=10), server_default='medium', nullable=False),
        sa.Column('confidence', sa.String(length=10), server_default='low', nullable=False),
        sa.Column('summary', sa.String(length=1000), nullable=True),
        sa.Column('impact', sa.String(length=1200), nullable=True),
        sa.Column('remediation', sa.String(length=1200), nullable=True),
        sa.Column('developer_note', sa.String(length=1000), nullable=True),
        sa.Column('cwe', sa.String(length=20), server_default='', nullable=False),
        sa.Column('owasp', sa.String(length=60), server_default='', nullable=False),
        # The analysis dies with the finding. It describes that row and nothing
        # else, so keeping it afterwards would leave an opinion about something
        # that no longer exists — unlike the audit log, which is deliberately
        # not a foreign key because the history has to outlive the row.
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['who_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        # One current reading per finding. Re-analysing replaces it; what was
        # applied from it lives in the audit log.
        sa.UniqueConstraint('finding_id', name='uq_ai_analyses_finding'),
    )
    op.create_index(op.f('ix_ai_analyses_id'), 'ai_analyses', ['id'])
    op.create_index(op.f('ix_ai_analyses_finding_id'), 'ai_analyses', ['finding_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_ai_analyses_finding_id'), table_name='ai_analyses')
    op.drop_index(op.f('ix_ai_analyses_id'), table_name='ai_analyses')
    op.drop_table('ai_analyses')
