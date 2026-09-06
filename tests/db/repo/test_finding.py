"""`FindingRepository.list_filtered` against a real in-memory SQLite table
— `Finding` has no Postgres-specific column types (no JSONB/ARRAY/pgvector,
unlike `Asset`/`Evidence`/`Verdict`), so it's one of the few tables this
project can exercise with a real repo and a real (if not Postgres) engine,
the same treatment `tests/recon/conftest.py`'s `audit_log_repo` fixture
gives `AuditLog`. `GET /api/findings` (Stage 10) is this method's caller.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from kiyooo.db.models import Finding, FindingDetector, FindingStatus, Severity
from kiyooo.db.repo.finding import FindingRepository

_NOW = datetime.now(UTC)


@pytest.fixture
async def finding_repo() -> AsyncIterator[FindingRepository]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Finding.__table__.create)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield FindingRepository(session)

    await engine.dispose()


def _finding(*, status: FindingStatus, scan_run_id: uuid.UUID, last_seen: datetime) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        scan_run_id=scan_run_id,
        asset_id=uuid.uuid4(),
        category_id="exposed-database",
        raw_severity=Severity.CRITICAL,
        title="Database exposed",
        detector=FindingDetector.RULE,
        fingerprint=f"fp-{uuid.uuid4()}",
        status=status,
        first_seen=_NOW,
        last_seen=last_seen,
    )


async def test_list_filtered_no_filters_returns_everything(
    finding_repo: FindingRepository,
) -> None:
    scan_run_id = uuid.uuid4()
    await finding_repo.add(
        _finding(status=FindingStatus.NEW, scan_run_id=scan_run_id, last_seen=_NOW)
    )
    await finding_repo.add(
        _finding(status=FindingStatus.TRIAGED, scan_run_id=scan_run_id, last_seen=_NOW)
    )

    results = await finding_repo.list_filtered()
    assert len(results) == 2


async def test_list_filtered_by_status(finding_repo: FindingRepository) -> None:
    scan_run_id = uuid.uuid4()
    await finding_repo.add(
        _finding(status=FindingStatus.NEW, scan_run_id=scan_run_id, last_seen=_NOW)
    )
    await finding_repo.add(
        _finding(status=FindingStatus.ROUTED, scan_run_id=scan_run_id, last_seen=_NOW)
    )

    results = await finding_repo.list_filtered(status=FindingStatus.ROUTED)
    assert len(results) == 1
    assert results[0].status == FindingStatus.ROUTED


async def test_list_filtered_by_scan_run_id(finding_repo: FindingRepository) -> None:
    run_a, run_b = uuid.uuid4(), uuid.uuid4()
    await finding_repo.add(_finding(status=FindingStatus.NEW, scan_run_id=run_a, last_seen=_NOW))
    await finding_repo.add(_finding(status=FindingStatus.NEW, scan_run_id=run_b, last_seen=_NOW))

    results = await finding_repo.list_filtered(scan_run_id=run_a)
    assert len(results) == 1
    assert results[0].scan_run_id == run_a


async def test_list_filtered_by_category_id(finding_repo: FindingRepository) -> None:
    scan_run_id = uuid.uuid4()
    other = _finding(status=FindingStatus.NEW, scan_run_id=scan_run_id, last_seen=_NOW)
    other.category_id = "exposed-mcp-server"
    await finding_repo.add(other)
    await finding_repo.add(
        _finding(status=FindingStatus.NEW, scan_run_id=scan_run_id, last_seen=_NOW)
    )

    results = await finding_repo.list_filtered(category_id="exposed-mcp-server")
    assert len(results) == 1
    assert results[0].category_id == "exposed-mcp-server"


async def test_list_filtered_orders_by_last_seen_descending(
    finding_repo: FindingRepository,
) -> None:
    scan_run_id = uuid.uuid4()
    older = await finding_repo.add(
        _finding(
            status=FindingStatus.NEW, scan_run_id=scan_run_id, last_seen=_NOW - timedelta(days=1)
        )
    )
    newer = await finding_repo.add(
        _finding(status=FindingStatus.NEW, scan_run_id=scan_run_id, last_seen=_NOW)
    )

    results = await finding_repo.list_filtered()
    assert [r.id for r in results] == [newer.id, older.id]


async def test_list_filtered_respects_limit(finding_repo: FindingRepository) -> None:
    scan_run_id = uuid.uuid4()
    for _ in range(5):
        await finding_repo.add(
            _finding(status=FindingStatus.NEW, scan_run_id=scan_run_id, last_seen=_NOW)
        )

    results = await finding_repo.list_filtered(limit=2)
    assert len(results) == 2
