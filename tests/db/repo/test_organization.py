"""`OrganizationRepository` against a real in-memory SQLite table —
`Organization` has no Postgres-specific column types (no JSONB/ARRAY/
pgvector), same treatment `tests/db/repo/test_finding.py` and
`tests/recon/conftest.py`'s `audit_log_repo` fixture give `Finding`/
`AuditLog`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from kiyooo.db.models import Organization, OrgRelationship
from kiyooo.db.repo.organization import OrganizationCreateError, OrganizationRepository

_NOW = datetime.now(UTC)


@pytest.fixture
async def org_repo() -> AsyncIterator[OrganizationRepository]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Organization.__table__.create)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield OrganizationRepository(session)

    await engine.dispose()


async def test_create_and_get_by_slug(org_repo: OrganizationRepository) -> None:
    created = await org_repo.create(
        slug="acme",
        name="Acme Corporation",
        relationship=OrgRelationship.SELF,
        parent_org_id=None,
        legal_entity_name=None,
        country=None,
        active_scanning_allowed=False,
        authorization_id=None,
        created_by="tester@example.com",
        created_at=_NOW,
    )
    found = await org_repo.get_by_slug("acme")
    assert found is not None
    assert found.id == created.id
    assert found.name == "Acme Corporation"


async def test_get_by_slug_missing_returns_none(org_repo: OrganizationRepository) -> None:
    assert await org_repo.get_by_slug("nope") is None


async def test_duplicate_slug_is_refused(org_repo: OrganizationRepository) -> None:
    await org_repo.create(
        slug="acme",
        name="Acme",
        relationship=OrgRelationship.SELF,
        parent_org_id=None,
        legal_entity_name=None,
        country=None,
        active_scanning_allowed=False,
        authorization_id=None,
        created_by="tester@example.com",
        created_at=_NOW,
    )
    with pytest.raises(OrganizationCreateError):
        await org_repo.create(
            slug="acme",
            name="Acme Again",
            relationship=OrgRelationship.SELF,
            parent_org_id=None,
            legal_entity_name=None,
            country=None,
            active_scanning_allowed=False,
            authorization_id=None,
            created_by="tester@example.com",
            created_at=_NOW,
        )


async def test_third_party_with_active_scanning_allowed_is_refused(
    org_repo: OrganizationRepository,
) -> None:
    """Mirrors `ScopeConfig._third_party_is_always_passive` — outward mode
    is passive-only structurally, enforced here since an org is created at
    CLI runtime, not loaded from a static file a pydantic validator gates.
    """
    with pytest.raises(OrganizationCreateError):
        await org_repo.create(
            slug="vendor-x",
            name="Vendor X",
            relationship=OrgRelationship.THIRD_PARTY,
            parent_org_id=None,
            legal_entity_name=None,
            country=None,
            active_scanning_allowed=True,
            authorization_id=None,
            created_by="tester@example.com",
            created_at=_NOW,
        )


async def test_third_party_without_active_scanning_allowed_succeeds(
    org_repo: OrganizationRepository,
) -> None:
    org = await org_repo.create(
        slug="vendor-x",
        name="Vendor X",
        relationship=OrgRelationship.THIRD_PARTY,
        parent_org_id=None,
        legal_entity_name=None,
        country=None,
        active_scanning_allowed=False,
        authorization_id=None,
        created_by="tester@example.com",
        created_at=_NOW,
    )
    assert org.active_scanning_allowed is False


async def test_list_children(org_repo: OrganizationRepository) -> None:
    parent = await org_repo.create(
        slug="acme",
        name="Acme",
        relationship=OrgRelationship.SELF,
        parent_org_id=None,
        legal_entity_name=None,
        country=None,
        active_scanning_allowed=False,
        authorization_id=None,
        created_by="tester@example.com",
        created_at=_NOW,
    )
    child = await org_repo.create(
        slug="acme-labs",
        name="Acme Labs",
        relationship=OrgRelationship.SUBSIDIARY,
        parent_org_id=parent.id,
        legal_entity_name="Acme Labs Ltd",
        country=None,
        active_scanning_allowed=False,
        authorization_id=None,
        created_by="tester@example.com",
        created_at=_NOW,
    )

    roots = await org_repo.list_children(None)
    assert [o.id for o in roots] == [parent.id]

    children = await org_repo.list_children(parent.id)
    assert [o.id for o in children] == [child.id]
