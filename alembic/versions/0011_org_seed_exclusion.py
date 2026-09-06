"""organization, seed, exclusion — kiyooo-easm-standalone.md Part D §1,
build item 1 (org + seed model, exclusions, ScopeGuard integration)

Revision ID: 0011
Revises: 0010
Create Date: 2026-09-01

Hand-written from the live kiyooo.db.models definitions, same as 0002 —
three new tables, no existing table touched. `organization` is created
first since both `seed.org_id` and `exclusion.org_id` (and
`organization.parent_org_id` itself) foreign-key into it.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SEED_KIND = sa.Enum(
    "APEX_DOMAIN",
    "WILDCARD",
    "SUBDOMAIN",
    "URL",
    "IP",
    "CIDR",
    "ASN",
    "CLOUD_ACCOUNT",
    "GITHUB_ORG",
    "SAAS_TENANT",
    "BRAND_TERM",
    "EMAIL_DOMAIN",
    name="seed_kind",
)


def upgrade() -> None:
    op.create_table(
        "organization",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("slug", sa.String(length=128), nullable=False),
        sa.Column("parent_org_id", sa.Uuid(), nullable=True),
        sa.Column(
            "relationship",
            sa.Enum(
                "SELF",
                "SUBSIDIARY",
                "ACQUISITION",
                "BRAND",
                "THIRD_PARTY",
                "PROSPECT",
                name="org_relationship",
            ),
            nullable=False,
        ),
        sa.Column("legal_entity_name", sa.String(length=256), nullable=True),
        sa.Column("country", sa.String(length=2), nullable=True),
        sa.Column("active_scanning_allowed", sa.Boolean(), nullable=False),
        sa.Column("authorization_id", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=256), nullable=False),
        sa.ForeignKeyConstraint(["parent_org_id"], ["organization.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug", name="uq_organization_slug"),
    )
    op.create_table(
        "seed",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("kind", _SEED_KIND, nullable=False),
        sa.Column("value", sa.String(length=2048), nullable=False),
        sa.Column(
            "scope_action", sa.Enum("INCLUDE", "EXCLUDE", name="scope_action"), nullable=False
        ),
        sa.Column("active_scan_allowed", sa.Boolean(), nullable=True),
        sa.Column("verified", sa.Boolean(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("added_by", sa.String(length=256), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organization.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "exclusion",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=True),
        sa.Column("kind", _SEED_KIND, nullable=False),
        sa.Column("value", sa.String(length=2048), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "source",
            sa.Enum(
                "SHIPPED_DEFAULT",
                "USER",
                "AUTO_CDN",
                "AUTO_SHARED_HOST",
                name="exclusion_source",
            ),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organization.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    # 0001/0002's downgrades drop tables only, leaving their enum types
    # orphaned in Postgres — harmless until a downgrade is followed by a
    # re-upgrade, which then fails with "type already exists" (reproduced
    # live while testing this migration). Dropping them here isn't just
    # tidiness, it's what makes downgrade->upgrade actually round-trip for
    # this migration, even though the earlier ones still don't.
    op.drop_table("exclusion")
    op.drop_table("seed")
    op.drop_table("organization")
    bind = op.get_bind()
    sa.Enum(name="exclusion_source").drop(bind, checkfirst=True)
    sa.Enum(name="scope_action").drop(bind, checkfirst=True)
    sa.Enum(name="seed_kind").drop(bind, checkfirst=True)
    sa.Enum(name="org_relationship").drop(bind, checkfirst=True)
