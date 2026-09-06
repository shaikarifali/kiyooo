"""ingest: evidence_kind.external_finding + finding_detector.external + scan_trigger.ingest

Revision ID: 0007
Revises: 0006
Create Date: 2026-08-07

Stage 1b needs a way to mark evidence and findings that came from a vendor
import rather than our own recon/detection pipeline, and a scan_run
trigger value for the synthetic scan_run each ingest batch is grouped
under (evidence/finding are both scan_run_id-scoped; an import has no
recon scan behind it, so it gets its own lightweight one).
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TYPE evidence_kind ADD VALUE IF NOT EXISTS 'EXTERNAL_FINDING'")
    op.execute("ALTER TYPE finding_detector ADD VALUE IF NOT EXISTS 'EXTERNAL'")
    op.execute("ALTER TYPE scan_trigger ADD VALUE IF NOT EXISTS 'INGEST'")


def downgrade() -> None:
    # Postgres has no ALTER TYPE ... DROP VALUE — same limitation noted in
    # migration 0003.
    pass
