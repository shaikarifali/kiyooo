"""pgvector extension + human_review.embedding, evidence.injection_suspected

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-07

Stage 5's `triage/memory.py` needs `human_review.embedding` (nomic-embed-text's
768-dim output — see `kiyooo.db.models._EMBEDDING_DIM`) for pgvector
similarity retrieval, and the `pgvector` extension itself. `evidence.
injection_suspected` is `normalize/injection.py`'s canary-scan output
 — existing rows default to `false`, not unknown, since a
scan that ran before this migration genuinely never flagged anything.
"""

from collections.abc import Sequence

import pgvector.sqlalchemy
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_EMBEDDING_DIM = 768


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.add_column(
        "human_review",
        sa.Column("embedding", pgvector.sqlalchemy.Vector(_EMBEDDING_DIM), nullable=True),
    )
    op.add_column(
        "evidence",
        sa.Column(
            "injection_suspected",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("evidence", "injection_suspected")
    op.drop_column("human_review", "embedding")
    # The extension is left in place — dropping it would break any other
    # table that came to depend on the `vector` type after this migration.
