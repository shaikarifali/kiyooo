from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select

from kiyooo.db.models import ChangeEvent
from kiyooo.db.repo.base import Repository


class ChangeEventRepository(Repository[ChangeEvent]):
    model = ChangeEvent

    async def for_scan_run(self, scan_run_id: UUID) -> list[ChangeEvent]:
        result = await self._session.execute(
            select(ChangeEvent).where(ChangeEvent.scan_run_id == scan_run_id)
        )
        return list(result.scalars().all())

    async def for_asset(self, asset_id: UUID) -> list[ChangeEvent]:
        result = await self._session.execute(
            select(ChangeEvent).where(ChangeEvent.asset_id == asset_id)
        )
        return list(result.scalars().all())

    async def since(self, cutoff: datetime) -> list[ChangeEvent]:
        result = await self._session.execute(
            select(ChangeEvent)
            .where(ChangeEvent.occurred_at >= cutoff)
            .order_by(ChangeEvent.occurred_at)
        )
        return list(result.scalars().all())
