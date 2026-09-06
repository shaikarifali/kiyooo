"""audit_log: finding_id column

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-07

Stage 6's `verify/executor.py` makes ScopeGuard checks on behalf of one
specific finding (a verification tool call the model requested), and the
DoD requires every verification call traceable back to that finding —
`audit_log` had no column for it, only `scan_run_id`.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("audit_log", sa.Column("finding_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        "fk_audit_log_finding_id",
        "audit_log",
        "finding",
        ["finding_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_audit_log_finding_id", "audit_log", type_="foreignkey")
    op.drop_column("audit_log", "finding_id")
