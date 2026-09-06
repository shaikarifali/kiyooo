"""asset_type: add notebook/ai_app/ai_saas_tenant

Revision ID: 0010
Revises: 0009
Create Date: 2026-08-08

Stage 11b's AI attack surface module. llm_endpoint/mcp_server/
model_registry/vector_db already existed from Stage 0's forward-looking
schema; these three round it out to Stage 11b's full named list.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TYPE asset_type ADD VALUE IF NOT EXISTS 'NOTEBOOK'")
    op.execute("ALTER TYPE asset_type ADD VALUE IF NOT EXISTS 'AI_APP'")
    op.execute("ALTER TYPE asset_type ADD VALUE IF NOT EXISTS 'AI_SAAS_TENANT'")


def downgrade() -> None:
    pass  # Postgres has no ALTER TYPE ... DROP VALUE
