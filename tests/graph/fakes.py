"""In-memory fakes for graph/diff tests. Asset, Evidence, AssetSnapshot, and
ChangeEvent all use Postgres-only column types (JSONB) — the same reason
Stage 1's orchestrator tests fake ScanRunRepository/EvidenceWriter rather
than hitting a real DB (see tests/recon/fakes.py). These fakes implement the
exact method signatures graph/builder.py, graph/snapshot.py, and
diff/engine.py call against the real repos.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from kiyooo.db.models import (
    Asset,
    AssetSnapshot,
    ChangeEvent,
    Evidence,
    ScanRun,
    ScanRunStatus,
    ScanTrigger,
)

if TYPE_CHECKING:
    from kiyooo.db.models import AssetType


class FakeAssetRepository:
    def __init__(self) -> None:
        self._by_id: dict[UUID, Asset] = {}

    async def get(self, id_: UUID) -> Asset | None:
        return self._by_id.get(id_)

    async def get_by_identity(self, type_: AssetType, value: str) -> Asset | None:
        for asset in self._by_id.values():
            if asset.type == type_ and asset.value == value:
                return asset
        return None

    async def get_by_value(self, value: str) -> Asset | None:
        for asset in self._by_id.values():
            if asset.value == value:
                return asset
        return None

    async def get_or_create(
        self,
        type_: AssetType,
        value: str,
        *,
        confidence_in_scope: float,
        scope_reason: str | None = None,
    ) -> Asset:
        existing = await self.get_by_identity(type_, value)
        now = datetime.now(UTC)
        if existing is not None:
            existing.last_seen = now
            existing.is_active = True
            return existing

        asset = Asset(
            id=uuid.uuid4(),
            type=type_,
            value=value,
            first_seen=now,
            last_seen=now,
            is_active=True,
            confidence_in_scope=confidence_in_scope,
            scope_reason=scope_reason,
            attributes={},
        )
        self._by_id[asset.id] = asset
        return asset

    async def list_active_last_seen_before(self, cutoff: datetime) -> list[Asset]:
        return [a for a in self._by_id.values() if a.is_active and a.last_seen < cutoff]

    async def mark_inactive(self, assets: list[Asset]) -> None:
        for asset in assets:
            asset.is_active = False


class FakeScanRunRepository:
    def __init__(self) -> None:
        self._runs: list[ScanRun] = []

    def add_completed(self, scan_run_id: UUID, started_at: datetime) -> None:
        self._runs.append(
            ScanRun(
                id=scan_run_id,
                started_at=started_at,
                finished_at=started_at,
                status=ScanRunStatus.COMPLETED,
                scope_hash="x",
                config_hash="x",
                trigger=ScanTrigger.MANUAL,
            )
        )

    async def recent_completed(self, limit: int) -> list[ScanRun]:
        return sorted(self._runs, key=lambda r: r.started_at, reverse=True)[:limit]


class FakeAssetSnapshotRepository:
    def __init__(self) -> None:
        self.snapshots: list[AssetSnapshot] = []

    async def add(self, snapshot: AssetSnapshot) -> AssetSnapshot:
        self.snapshots.append(snapshot)
        return snapshot

    async def for_scan_run(self, scan_run_id: UUID) -> list[AssetSnapshot]:
        return [s for s in self.snapshots if s.scan_run_id == scan_run_id]

    async def latest_before(
        self, asset_id: UUID, *, exclude_scan_run_id: UUID
    ) -> AssetSnapshot | None:
        candidates = [
            s
            for s in self.snapshots
            if s.asset_id == asset_id and s.scan_run_id != exclude_scan_run_id
        ]
        return max(candidates, key=lambda s: s.observed_at, default=None)


class FakeEvidenceRepository:
    def __init__(self) -> None:
        self._evidence: list[Evidence] = []

    def seed(self, evidence: list[Evidence]) -> None:
        self._evidence.extend(evidence)

    async def for_scan_run(self, scan_run_id: UUID) -> list[Evidence]:
        return [e for e in self._evidence if e.scan_run_id == scan_run_id]

    async def add(self, evidence: Evidence) -> Evidence:
        self._evidence.append(evidence)
        return evidence


class FakeChangeEventRepository:
    def __init__(self) -> None:
        self.events: list[ChangeEvent] = []

    async def add(self, event: ChangeEvent) -> ChangeEvent:
        self.events.append(event)
        return event
