from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from kiyooo.db.models import Evidence
from kiyooo.db.repo.base import Repository


class EvidenceRepository(Repository[Evidence]):
    model = Evidence

    async def for_scan_run(self, scan_run_id: UUID) -> list[Evidence]:
        result = await self._session.execute(
            select(Evidence).where(Evidence.scan_run_id == scan_run_id)
        )
        return list(result.scalars().all())

    async def for_asset(self, asset_id: UUID) -> list[Evidence]:
        result = await self._session.execute(select(Evidence).where(Evidence.asset_id == asset_id))
        return list(result.scalars().all())
