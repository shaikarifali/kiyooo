"""module_toggle: attack-surface module on/off switches

Revision ID: 0018
Revises: 0017
Create Date: 2026-09-06

New table, not an enum change — the "add all these attack surfaces to the
UI, but let the user turn each on/off" ask. Seeds one enabled=True row per
Stage 13-17 domain module so existing installs keep their current
behavior (everything visible) until someone opts to turn one off.
"""

from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_MODULE_KEYS = ("cloud", "containers", "repos", "mobile", "attack_paths")


def upgrade() -> None:
    op.create_table(
        "module_toggle",
        sa.Column("module_key", sa.String(length=64), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    module_toggle = sa.table(
        "module_toggle",
        sa.column("module_key", sa.String),
        sa.column("enabled", sa.Boolean),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    now = datetime.now(UTC)
    op.bulk_insert(
        module_toggle,
        [{"module_key": key, "enabled": True, "updated_at": now} for key in _MODULE_KEYS],
    )


def downgrade() -> None:
    op.drop_table("module_toggle")
