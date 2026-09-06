"""`ExclusionRepository` against a real in-memory SQLite table —
`Exclusion` has no Postgres-specific column types, same treatment
`test_finding.py` gives `Finding`.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from kiyooo.db.models import Exclusion, ExclusionSource, SeedKind
from kiyooo.db.repo.exclusion import ExclusionRepository

_NOW = datetime.now(UTC)


@pytest.fixture
async def exclusion_repo() -> AsyncIterator[ExclusionRepository]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Exclusion.__table__.create)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield ExclusionRepository(session)

    await engine.dispose()


async def test_create_global_exclusion_has_no_org_id(
    exclusion_repo: ExclusionRepository,
) -> None:
    excl = await exclusion_repo.create(
        org_id=None,
        kind=SeedKind.APEX_DOMAIN,
        value="always-excluded.test",
        reason="shipped default",
        source=ExclusionSource.SHIPPED_DEFAULT,
        created_at=_NOW,
    )
    assert excl.org_id is None


async def test_list_for_org_and_global_returns_both(exclusion_repo: ExclusionRepository) -> None:
    org_id = uuid.uuid4()
    other_org_id = uuid.uuid4()
    await exclusion_repo.create(
        org_id=org_id,
        kind=SeedKind.APEX_DOMAIN,
        value="org-specific.example.com",
        reason="internal only",
        source=ExclusionSource.USER,
        created_at=_NOW,
    )
    await exclusion_repo.create(
        org_id=None,
        kind=SeedKind.APEX_DOMAIN,
        value="global.test",
        reason="shipped default",
        source=ExclusionSource.SHIPPED_DEFAULT,
        created_at=_NOW,
    )
    await exclusion_repo.create(
        org_id=other_org_id,
        kind=SeedKind.APEX_DOMAIN,
        value="not-mine.example.com",
        reason="someone else's",
        source=ExclusionSource.USER,
        created_at=_NOW,
    )

    values = {e.value for e in await exclusion_repo.list_for_org_and_global(org_id)}
    assert values == {"org-specific.example.com", "global.test"}


async def test_list_global_returns_only_global(exclusion_repo: ExclusionRepository) -> None:
    org_id = uuid.uuid4()
    await exclusion_repo.create(
        org_id=org_id,
        kind=SeedKind.APEX_DOMAIN,
        value="org-specific.example.com",
        reason="internal only",
        source=ExclusionSource.USER,
        created_at=_NOW,
    )
    await exclusion_repo.create(
        org_id=None,
        kind=SeedKind.APEX_DOMAIN,
        value="global.test",
        reason="shipped default",
        source=ExclusionSource.SHIPPED_DEFAULT,
        created_at=_NOW,
    )

    values = [e.value for e in await exclusion_repo.list_global()]
    assert values == ["global.test"]
