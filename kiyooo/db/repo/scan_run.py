from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select

from kiyooo.db.models import ScanRun, ScanRunStatus
from kiyooo.db.repo.base import Repository


class ScanRunRepository(Repository[ScanRun]):
    model = ScanRun

    async def mark_status(
        self, scan_run_id: UUID, status: ScanRunStatus, *, finished_at: datetime | None = None
    ) -> None:
        scan_run = await self.get(scan_run_id)
        if scan_run is None:
            raise ValueError(f"scan_run {scan_run_id} not found")
        scan_run.status = status
        if finished_at is not None:
            scan_run.finished_at = finished_at
        await self._session.flush()

    async def recent_completed(self, limit: int) -> list[ScanRun]:
        result = await self._session.execute(
            select(ScanRun)
            .where(ScanRun.status == ScanRunStatus.COMPLETED)
            .order_by(ScanRun.started_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())
