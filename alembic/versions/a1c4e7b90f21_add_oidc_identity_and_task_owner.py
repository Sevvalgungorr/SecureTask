"""Add OIDC identity to users and owner to tasks

Revision ID: a1c4e7b90f21
Revises: d30a191589d8
Create Date: 2026-07-20 13:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1c4e7b90f21'
down_revision: Union[str, Sequence[str], None] = 'd30a191589d8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _count(table: str) -> int:
    bind = op.get_bind()

    return bind.execute(sa.text(f"SELECT count(*) FROM {table}")).scalar_one()


def upgrade() -> None:
    """Upgrade schema."""
    # The new NOT NULL columns have no sensible backfill: an existing user has
    # no provider subject, and an existing task has no owner. Rather than guess
    # or discard rows, refuse to run and let an operator decide.
    if _count("users"):
        raise RuntimeError(
            "users table is not empty; existing rows have no OIDC identity to "
            "backfill. Migrate or remove them before running this revision."
        )

    if _count("tasks"):
        raise RuntimeError(
            "tasks table is not empty; existing rows have no owner to backfill. "
            "Assign owners or remove them before running this revision."
        )

    op.add_column('users', sa.Column('oidc_issuer', sa.String(length=255), nullable=False))
    op.add_column('users', sa.Column('oidc_sub', sa.String(length=255), nullable=False))

    op.alter_column('users', 'username',
                    existing_type=sa.String(length=50),
                    type_=sa.String(length=255),
                    existing_nullable=False)
    op.alter_column('users', 'email',
                    existing_type=sa.String(length=255),
                    nullable=True)
    op.alter_column('users', 'hashed_password',
                    existing_type=sa.String(length=255),
                    nullable=True)

    # Name and email are not unique per provider account; identity is.
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=False)
    op.create_index(op.f('ix_users_oidc_issuer'), 'users', ['oidc_issuer'], unique=False)
    op.create_index(op.f('ix_users_oidc_sub'), 'users', ['oidc_sub'], unique=False)
    op.create_unique_constraint('uq_users_oidc_identity', 'users', ['oidc_issuer', 'oidc_sub'])

    op.add_column('tasks', sa.Column('owner_id', sa.Integer(), nullable=False))
    op.create_index(op.f('ix_tasks_owner_id'), 'tasks', ['owner_id'], unique=False)
    op.create_foreign_key(
        'fk_tasks_owner_id_users', 'tasks', 'users',
        ['owner_id'], ['id'], ondelete='CASCADE',
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint('fk_tasks_owner_id_users', 'tasks', type_='foreignkey')
    op.drop_index(op.f('ix_tasks_owner_id'), table_name='tasks')
    op.drop_column('tasks', 'owner_id')

    op.drop_constraint('uq_users_oidc_identity', 'users', type_='unique')
    op.drop_index(op.f('ix_users_oidc_sub'), table_name='users')
    op.drop_index(op.f('ix_users_oidc_issuer'), table_name='users')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)

    op.alter_column('users', 'hashed_password',
                    existing_type=sa.String(length=255),
                    nullable=False)
    op.alter_column('users', 'email',
                    existing_type=sa.String(length=255),
                    nullable=False)
    op.alter_column('users', 'username',
                    existing_type=sa.String(length=255),
                    type_=sa.String(length=50),
                    existing_nullable=False)

    op.drop_column('users', 'oidc_sub')
    op.drop_column('users', 'oidc_issuer')
