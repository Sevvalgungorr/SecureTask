"""Start and stop times for a finding's remediation window

A deadline on its own only says how much time is left. With the start, the same
row says how much of the window has been used — and with the stop, whether the
window was met at all, which is the number every remediation SLA exists to
produce.

Revision ID: b4e9a2f76c15
Revises: c8b1e6f04a37
Create Date: 2026-08-18 11:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b4e9a2f76c15'
down_revision: Union[str, Sequence[str], None] = 'c8b1e6f04a37'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'findings',
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.add_column('findings', sa.Column('closed_at', sa.DateTime(timezone=True)))

    # Existing rows just took now() as their creation time, which would make
    # every finding in the database look like it was filed today. The audit log
    # knows better: it wrote a line the moment each one was created.
    op.execute(
        """
        UPDATE findings AS f
           SET created_at = a.filed_at
          FROM (
                SELECT finding_id, MIN(created_at) AS filed_at
                  FROM audit_logs
                 WHERE action = 'created' AND finding_id IS NOT NULL
              GROUP BY finding_id
               ) AS a
         WHERE a.finding_id = f.id
        """
    )

    # An accepted risk already records exactly when it was accepted, and that
    # is the moment it left the list.
    op.execute(
        """
        UPDATE findings
           SET closed_at = accepted_at
         WHERE status = 'accepted_risk' AND accepted_at IS NOT NULL
        """
    )

    # Rows already marked fixed are deliberately left null. The last audit line
    # about a finding is not necessarily the one that closed it, and a guessed
    # close time would be read as a measured one — "closed on time" is a claim,
    # and it should only be made where it is known. Null renders as "kapatıldı"
    # with no date, which is the honest answer for rows that predate this.


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('findings', 'closed_at')
    op.drop_column('findings', 'created_at')
