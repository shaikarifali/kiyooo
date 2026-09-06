"""external_finding_source: add name

Revision ID: 0013
Revises: 0012
Create Date: 2026-09-02

`system` alone identified a source uniquely only while every source was
one of the hand-written adapters (one row per vendor). The generic,
config-driven `CUSTOM` connector (`ingest/adapters/generic_rest.py`)
lets an org point kiyooo at any number of REST-emitting ASM/VM tools —
so sources need a human label. Backfill existing rows from `system`
(the only rows that can exist before this migration are the ones the
CLI's `get_or_create(system)` created) before making it required.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("external_finding_source", sa.Column("name", sa.String(length=256)))
    op.execute("UPDATE external_finding_source SET name = system::text WHERE name IS NULL")
    op.alter_column("external_finding_source", "name", nullable=False)


def downgrade() -> None:
    op.drop_column("external_finding_source", "name")
