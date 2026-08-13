"""Teams, assignment, and the role that may accept a risk

Until now one person filed a finding, worked it and closed it. Every control
built on top of that — the second factor, the written reason, the chained log —
constrains somebody, and there was nobody to constrain. Teams put a second
person in the room: a finding belongs to a team, someone is assigned to it, and
only a risk owner who did not file it may accept its risk.

Existing findings keep team_id NULL and stay personal, visible to their
reporter alone. Nothing is moved into a team automatically: which team a
finding belongs to is a statement about who may see it, and this migration has
no way to know the answer.

Revision ID: d7f3a1c95e42
Revises: b4c8e2f19d05
Create Date: 2026-08-13 12:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd7f3a1c95e42'
down_revision: Union[str, Sequence[str], None] = 'b4c8e2f19d05'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'teams',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column(
            'created_at', sa.DateTime(timezone=True),
            server_default=sa.text('now()'), nullable=False,
        ),
        sa.Column('created_by_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name', name='uq_teams_name'),
    )
    op.create_index('ix_teams_id', 'teams', ['id'])

    op.create_table(
        'team_members',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('role', sa.String(length=20), server_default='member', nullable=False),
        sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('team_id', 'user_id', name='uq_team_members_team_user'),
    )
    op.create_index('ix_team_members_id', 'team_members', ['id'])
    op.create_index('ix_team_members_team_id', 'team_members', ['team_id'])
    op.create_index('ix_team_members_user_id', 'team_members', ['user_id'])

    op.add_column('findings', sa.Column('team_id', sa.Integer(), nullable=True))
    op.add_column('findings', sa.Column('assignee_id', sa.Integer(), nullable=True))
    op.create_index('ix_findings_team_id', 'findings', ['team_id'])
    op.create_foreign_key(
        'fk_findings_team', 'findings', 'teams', ['team_id'], ['id'], ondelete='SET NULL',
    )
    op.create_foreign_key(
        'fk_findings_assignee', 'findings', 'users', ['assignee_id'], ['id'],
        ondelete='SET NULL',
    )


def downgrade() -> None:
    """Downgrade schema.

    Dropping the columns loses which team a finding belonged to and who was
    working it. The audit log keeps both — assignment and acceptance are
    written there as they happen — so the history survives the rollback even
    though the current state does not.
    """
    op.drop_constraint('fk_findings_assignee', 'findings', type_='foreignkey')
    op.drop_constraint('fk_findings_team', 'findings', type_='foreignkey')
    op.drop_index('ix_findings_team_id', table_name='findings')
    op.drop_column('findings', 'assignee_id')
    op.drop_column('findings', 'team_id')

    op.drop_index('ix_team_members_user_id', table_name='team_members')
    op.drop_index('ix_team_members_team_id', table_name='team_members')
    op.drop_index('ix_team_members_id', table_name='team_members')
    op.drop_table('team_members')

    op.drop_index('ix_teams_id', table_name='teams')
    op.drop_table('teams')
