"""`ModelPinRepository` against a real in-memory SQLite table — `ModelPin`
has no Postgres-specific column types, same treatment `test_finding.py`
gives `Finding`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from kiyooo.db.models import ModelPin, ModelPinRole
from kiyooo.db.repo.model_pin import ModelPinRepository

_NOW = datetime.now(UTC)


@pytest.fixture
async def model_pin_repo() -> AsyncIterator[ModelPinRepository]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(ModelPin.__table__.create)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield ModelPinRepository(session)

    await engine.dispose()


async def test_pin_creates_a_row_with_no_endpoint_for_a_built_in_provider(
    model_pin_repo: ModelPinRepository,
) -> None:
    pin = await model_pin_repo.pin(
        role=ModelPinRole.BULK,
        provider="ollama",
        model="llama3.1:8b",
        digest="llama3.1:8b",
        pinned_by="tester@example.com",
        changelog_note="initial pin",
        pinned_at=_NOW,
    )
    assert pin.endpoint_url is None
    assert pin.credential_ref is None
    assert pin.superseded_by is None


async def test_pin_stores_endpoint_and_credential_ref_for_bring_your_own_provider(
    model_pin_repo: ModelPinRepository,
) -> None:
    pin = await model_pin_repo.pin(
        role=ModelPinRole.BULK,
        provider="openrouter",
        model="some/model",
        digest="some/model",
        pinned_by="tester@example.com",
        changelog_note="trying a bring-your-own provider",
        pinned_at=_NOW,
        endpoint_url="https://openrouter.ai/api/v1",
        credential_ref="env:OPENROUTER_API_KEY",
    )
    assert pin.endpoint_url == "https://openrouter.ai/api/v1"
    assert pin.credential_ref == "env:OPENROUTER_API_KEY"


async def test_get_active_returns_none_when_nothing_pinned(
    model_pin_repo: ModelPinRepository,
) -> None:
    assert await model_pin_repo.get_active(ModelPinRole.BULK) is None


async def test_pin_supersedes_the_previous_active_pin_for_the_same_role(
    model_pin_repo: ModelPinRepository,
) -> None:
    first = await model_pin_repo.pin(
        role=ModelPinRole.BULK,
        provider="ollama",
        model="llama3.1:8b",
        digest="llama3.1:8b",
        pinned_by="tester@example.com",
        changelog_note="first pin",
        pinned_at=_NOW,
    )
    second = await model_pin_repo.pin(
        role=ModelPinRole.BULK,
        provider="anthropic",
        model="claude-sonnet-5",
        digest="claude-sonnet-5",
        pinned_by="tester@example.com",
        changelog_note="switching to hosted",
        pinned_at=_NOW,
    )

    refreshed_first = await model_pin_repo.get(first.id)
    assert refreshed_first is not None
    assert refreshed_first.superseded_by == second.id

    active = await model_pin_repo.get_active(ModelPinRole.BULK)
    assert active is not None
    assert active.id == second.id


async def test_pinning_one_role_does_not_affect_another(
    model_pin_repo: ModelPinRepository,
) -> None:
    await model_pin_repo.pin(
        role=ModelPinRole.BULK,
        provider="ollama",
        model="llama3.1:8b",
        digest="llama3.1:8b",
        pinned_by="tester@example.com",
        changelog_note="bulk pin",
        pinned_at=_NOW,
    )
    assert await model_pin_repo.get_active(ModelPinRole.ESCALATION) is None


async def test_list_active_returns_one_row_per_pinned_role(
    model_pin_repo: ModelPinRepository,
) -> None:
    await model_pin_repo.pin(
        role=ModelPinRole.BULK,
        provider="ollama",
        model="llama3.1:8b",
        digest="llama3.1:8b",
        pinned_by="tester@example.com",
        changelog_note="bulk pin",
        pinned_at=_NOW,
    )
    await model_pin_repo.pin(
        role=ModelPinRole.ESCALATION,
        provider="anthropic",
        model="claude-sonnet-5",
        digest="claude-sonnet-5",
        pinned_by="tester@example.com",
        changelog_note="escalation pin",
        pinned_at=_NOW,
    )

    active = await model_pin_repo.list_active()
    assert {p.role for p in active} == {ModelPinRole.BULK, ModelPinRole.ESCALATION}
