"""external_finding_system: add mobile_static

Revision ID: 0017
Revises: 0016
Create Date: 2026-09-06

Stage 16 — mobile static analysis. Same uppercase-member-name
convention as 0010/0014/0015/0016.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TYPE external_finding_system ADD VALUE IF NOT EXISTS 'MOBILE_STATIC'")


def downgrade() -> None:
    pass  # Postgres has no ALTER TYPE ... DROP VALUE
