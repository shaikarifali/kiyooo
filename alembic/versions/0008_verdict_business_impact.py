"""verdict: business_impact_hypothesis column

Revision ID: 0008
Revises: 0007
Create Date: 2026-08-07

Stage 7's ticket contract requires a "why it matters here" block (business
impact + environment + data sensitivity). The LLM already produces
`business_impact_hypothesis` on every verdict (`VerdictSchema` requires it)
but nothing persisted it — `triage/agent.py` computed it and dropped it.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "verdict",
        sa.Column("business_impact_hypothesis", sa.Text(), nullable=False, server_default=""),
    )
    op.alter_column("verdict", "business_impact_hypothesis", server_default=None)


def downgrade() -> None:
    op.drop_column("verdict", "business_impact_hypothesis")
