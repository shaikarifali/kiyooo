"""ticket_system: add 'webhook' value

Revision ID: 0009
Revises: 0008
Create Date: 2026-08-07

Stage 7's generic-webhook sink has no vendor tenant to test against
(same rationale as Stage 1b's CSV importer) so it's one of the two real
sinks — but `ticket_system` only had jira/linear/github/servicenow.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TYPE ticket_system ADD VALUE IF NOT EXISTS 'WEBHOOK'")


def downgrade() -> None:
    pass  # Postgres has no ALTER TYPE ... DROP VALUE
