"""asset_type: add container_image/k8s_cluster/k8s_workload;
external_finding_system: add trivy

Revision ID: 0015
Revises: 0014
Create Date: 2026-09-06

Stage 14 — containers/Kubernetes via Trivy (OSS, Apache-2.0).
Same uppercase-member-name convention as 0010/0014 (SQLAlchemy's `Enum`
stores `.name`, not `.value`, with no `values_callable` set on either
column).
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TYPE asset_type ADD VALUE IF NOT EXISTS 'CONTAINER_IMAGE'")
    op.execute("ALTER TYPE asset_type ADD VALUE IF NOT EXISTS 'K8S_CLUSTER'")
    op.execute("ALTER TYPE asset_type ADD VALUE IF NOT EXISTS 'K8S_WORKLOAD'")
    op.execute("ALTER TYPE external_finding_system ADD VALUE IF NOT EXISTS 'TRIVY'")


def downgrade() -> None:
    pass  # Postgres has no ALTER TYPE ... DROP VALUE
