"""`SeedRepository` against a real in-memory SQLite table — `Seed` has no
Postgres-specific column types, same treatment `test_finding.py` gives
`Finding`.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from kiyooo.db.models import ScopeAction, Seed, SeedKind
from kiyooo.db.repo.seed import SeedRepository

_NOW = datetime.now(UTC)


@pytest.fixture
async def seed_repo() -> AsyncIterator[SeedRepository]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Seed.__table__.create)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield SeedRepository(session)

    await engine.dispose()


def _org_id() -> uuid.UUID:
    return uuid.uuid4()


async def test_create_defaults_unverified_and_enabled(seed_repo: SeedRepository) -> None:
    org_id = _org_id()
    seed = await seed_repo.create(
        org_id=org_id,
        kind=SeedKind.APEX_DOMAIN,
        value="example.com",
        scope_action=ScopeAction.INCLUDE,
        active_scan_allowed=None,
        note=None,
        added_by="tester@example.com",
        added_at=_NOW,
    )
    assert seed.verified is False
    assert seed.disabled_at is None


async def test_list_for_org_only_returns_that_org(seed_repo: SeedRepository) -> None:
    org_a, org_b = _org_id(), _org_id()
    await seed_repo.create(
        org_id=org_a,
        kind=SeedKind.APEX_DOMAIN,
        value="a.com",
        scope_action=ScopeAction.INCLUDE,
        active_scan_allowed=None,
        note=None,
        added_by="t@example.com",
        added_at=_NOW,
    )
    await seed_repo.create(
        org_id=org_b,
        kind=SeedKind.APEX_DOMAIN,
        value="b.com",
        scope_action=ScopeAction.INCLUDE,
        active_scan_allowed=None,
        note=None,
        added_by="t@example.com",
        added_at=_NOW,
    )
    seeds = await seed_repo.list_for_org(org_a)
    assert [s.value for s in seeds] == ["a.com"]


async def test_list_for_org_excludes_disabled_by_default(seed_repo: SeedRepository) -> None:
    org_id = _org_id()
    seed = await seed_repo.create(
        org_id=org_id,
        kind=SeedKind.APEX_DOMAIN,
        value="a.com",
        scope_action=ScopeAction.INCLUDE,
        active_scan_allowed=None,
        note=None,
        added_by="t@example.com",
        added_at=_NOW,
    )
    await seed_repo.disable(seed.id, disabled_at=_NOW)

    assert await seed_repo.list_for_org(org_id) == []
    assert len(await seed_repo.list_for_org(org_id, include_disabled=True)) == 1


async def test_disable_sets_disabled_at_not_a_hard_delete(seed_repo: SeedRepository) -> None:
    org_id = _org_id()
    seed = await seed_repo.create(
        org_id=org_id,
        kind=SeedKind.APEX_DOMAIN,
        value="a.com",
        scope_action=ScopeAction.INCLUDE,
        active_scan_allowed=None,
        note=None,
        added_by="t@example.com",
        added_at=_NOW,
    )
    disabled = await seed_repo.disable(seed.id, disabled_at=_NOW)
    assert disabled.disabled_at == _NOW
    # still fetchable directly — nothing was deleted.
    assert await seed_repo.get(seed.id) is not None


async def test_disable_missing_seed_raises(seed_repo: SeedRepository) -> None:
    with pytest.raises(ValueError, match="not found"):
        await seed_repo.disable(uuid.uuid4(), disabled_at=_NOW)
