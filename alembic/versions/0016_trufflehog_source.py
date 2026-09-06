"""external_finding_system: add trufflehog

Revision ID: 0016
Revises: 0015
Create Date: 2026-09-06

Stage 15 — source code & supply chain via TruffleHog (OSS
engine, AGPL-3.0). Same uppercase-member-name convention as 0010/0014/0015.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TYPE external_finding_system ADD VALUE IF NOT EXISTS 'TRUFFLEHOG'")


def downgrade() -> None:
    pass  # Postgres has no ALTER TYPE ... DROP VALUE
