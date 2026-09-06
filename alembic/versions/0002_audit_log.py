"""audit_log — append-only ScopeGuard decision trail

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-06

Hand-written from the live kiyooo.db.models.AuditLog definition (verified by
compiling CreateTable against the postgresql dialect) rather than
autogenerate, because the reflection trick used for 0001 needs a real
connection to diff against and this one new table doesn't warrant standing up
a throwaway schema just to redo that diff.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=True),
        sa.Column("tool", sa.String(length=128), nullable=False),
        sa.Column("target", sa.String(length=2048), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column(
            "decision",
            sa.Enum("ALLOW", "DENY", "REQUIRES_CONFIRM", name="scope_decision"),
            nullable=False,
        ),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_run.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("audit_log")
