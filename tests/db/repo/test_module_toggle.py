"""`ModuleToggleRepository` against a real in-memory SQLite table —
`ModuleToggle` has no Postgres-specific column types, same treatment
`test_model_pin.py` gives `ModelPin`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from kiyooo.db.models import ModuleToggle
from kiyooo.db.repo.module_toggle import MODULE_KEYS, ModuleToggleRepository

_NOW = datetime.now(UTC)


@pytest.fixture
async def module_toggle_repo() -> AsyncIterator[ModuleToggleRepository]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(ModuleToggle.__table__.create)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield ModuleToggleRepository(session)

    await engine.dispose()


async def test_module_keys_covers_every_stage_13_to_17_domain_page() -> None:
    assert set(MODULE_KEYS) == {"cloud", "containers", "repos", "mobile", "attack_paths"}


async def test_set_enabled_creates_a_row_when_none_exists(
    module_toggle_repo: ModuleToggleRepository,
) -> None:
    toggle = await module_toggle_repo.set_enabled("cloud", enabled=False, updated_at=_NOW)

    assert toggle.module_key == "cloud"
    assert toggle.enabled is False
    assert await module_toggle_repo.get("cloud") is not None


async def test_set_enabled_flips_an_existing_row_in_place(
    module_toggle_repo: ModuleToggleRepository,
) -> None:
    await module_toggle_repo.set_enabled("mobile", enabled=True, updated_at=_NOW)

    flipped = await module_toggle_repo.set_enabled("mobile", enabled=False, updated_at=_NOW)

    assert flipped.enabled is False
    rows = await module_toggle_repo.list_all()
    assert len(rows) == 1


async def test_list_all_orders_by_module_key(
    module_toggle_repo: ModuleToggleRepository,
) -> None:
    await module_toggle_repo.set_enabled("repos", enabled=True, updated_at=_NOW)
    await module_toggle_repo.set_enabled("attack_paths", enabled=True, updated_at=_NOW)
    await module_toggle_repo.set_enabled("cloud", enabled=True, updated_at=_NOW)

    rows = await module_toggle_repo.list_all()

    assert [r.module_key for r in rows] == ["attack_paths", "cloud", "repos"]
