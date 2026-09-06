"""model_pin: add endpoint_url, credential_ref — bring-your-own-model

Revision ID: 0012
Revises: 0011
Create Date: 2026-09-02

`provider` was already free text, not a closed enum — the gap was that
anything other than "ollama"/"anthropic" had nowhere to record which
endpoint to call or which env var holds its credential. These two
nullable columns close that: NULL for the two built-in providers (they
have a default), required in practice for any bring-your-own provider.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("model_pin", sa.Column("endpoint_url", sa.String(length=512), nullable=True))
    op.add_column("model_pin", sa.Column("credential_ref", sa.String(length=128), nullable=True))


def downgrade() -> None:
    op.drop_column("model_pin", "credential_ref")
    op.drop_column("model_pin", "endpoint_url")
