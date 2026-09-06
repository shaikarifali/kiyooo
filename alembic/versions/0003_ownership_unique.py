"""ownership: 3 new sources + unique(asset_id, source)

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-07

Stage 3 adds three ownership sources the design's confidence table names but
the original enum didn't have slots for (TEAM_PATTERN, GIT_BLAME,
SIBLING_ASSET — see kiyooo.db.models.OwnershipSource's docstring), plus a
uniqueness constraint: one candidate row per (asset, source), so re-running
enrichment updates a source's existing candidate instead of accumulating
duplicates. `ALTER TYPE ... ADD VALUE` is safe in the same transaction as the
constraint here because the constraint doesn't reference the new enum values
themselves, only the column — no autocommit block needed.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_NEW_SOURCE_VALUES = ("TEAM_PATTERN", "GIT_BLAME", "SIBLING_ASSET")


def upgrade() -> None:
    for value in _NEW_SOURCE_VALUES:
        op.execute(f"ALTER TYPE ownership_source ADD VALUE IF NOT EXISTS '{value}'")
    op.create_unique_constraint("uq_ownership_asset_source", "ownership", ["asset_id", "source"])


def downgrade() -> None:
    # Postgres has no ALTER TYPE ... DROP VALUE — removing an enum value
    # requires rebuilding the type, which isn't safe to do blind (existing
    # rows might use it). The unique constraint is safe to drop either way.
    op.drop_constraint("uq_ownership_asset_source", "ownership", type_="unique")
