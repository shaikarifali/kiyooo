from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from kiyooo.db.models import AuditLog
from kiyooo.db.repo.audit_log import AuditLogRepository


@pytest.fixture
async def audit_log_repo() -> AsyncIterator[AuditLogRepository]:
    """A real `AuditLogRepository` backed by an in-memory SQLite table.

    `AuditLog` has no Postgres-specific column types (no JSONB, no ARRAY) —
    unlike `Asset` or `Evidence`, it can be created and queried against SQLite
    directly. This lets `ScopeGuard` tests exercise the real audit-write path
    with no live Postgres in the loop, without resorting to a mock.
    """
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(AuditLog.__table__.create)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield AuditLogRepository(session)

    await engine.dispose()
