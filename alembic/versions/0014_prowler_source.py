"""external_finding_system: add prowler

Revision ID: 0014
Revises: 0013
Create Date: 2026-09-06

Stage 13 — cloud posture via Prowler (OSS, Apache-2.0). SQLAlchemy's
`Enum` stores a Python enum member's `.name`, not its `.value`, by default (no
`values_callable` is set on this column — see e.g. 'MANDIANT_ASM' in
0001_initial.py) — so the new Postgres enum label is the uppercase member
name 'PROWLER', matching migration 0010's identical `asset_type` pattern.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TYPE external_finding_system ADD VALUE IF NOT EXISTS 'PROWLER'")


def downgrade() -> None:
    pass  # Postgres has no ALTER TYPE ... DROP VALUE
