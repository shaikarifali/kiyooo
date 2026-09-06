"""control: unique(asset_id, control_id)

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-07

Stage 4's `detect/controls.py` re-evaluates every control against every
asset on each scan; without this constraint, re-running detection would
insert a fresh `control` row every time instead of updating the existing
one's `detected_at`/`evidence_id` — the same idempotency fix Stage 3 made
for `ownership` (migration 0003).
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_unique_constraint("uq_control_asset_control", "control", ["asset_id", "control_id"])


def downgrade() -> None:
    op.drop_constraint("uq_control_asset_control", "control", type_="unique")
