"""Scanner metadata for SCA and secret scanning

Two columns, both because the alternative was worse.

`findings.details` holds what one scanner reported that has no field of its
own: the package, installed version and fixed version behind a dependency
vulnerability; the rule and the kind of credential behind a leaked secret. The
alternative was six nullable columns that are empty for every finding a person
typed in and every finding a network scan produced.

It is JSON rather than JSONB. This application only ever reads the whole
document back out — nothing queries inside it — and JSON preserves the order
the keys were written in, which is the order the interface displays them.

`scan_runs.note` holds something true about a run that is not an error: how
many requirement lines were skipped because they were not pinned to an exact
version. Without it, an audit that examined 20 of 24 dependencies reports "no
vulnerabilities" and is believed.

Revision ID: b8e4f21d9a37
Revises: c6d1f83a52be
Create Date: 2026-08-25

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'b8e4f21d9a37'
down_revision: Union[str, Sequence[str], None] = 'c6d1f83a52be'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('findings', sa.Column('details', sa.JSON(), nullable=True))
    op.add_column(
        'scan_runs',
        sa.Column('note', sa.String(length=200), nullable=False, server_default=''),
    )


def downgrade() -> None:
    op.drop_column('scan_runs', 'note')
    op.drop_column('findings', 'details')
