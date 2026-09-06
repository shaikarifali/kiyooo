from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from kiyooo.db.models import AssetSnapshot
from kiyooo.db.repo.base import Repository


class AssetSnapshotRepository(Repository[AssetSnapshot]):
    model = AssetSnapshot

    async def latest_before(
        self, asset_id: UUID, *, exclude_scan_run_id: UUID
    ) -> AssetSnapshot | None:
        """The most recent snapshot for this asset from any scan *other* than
        `exclude_scan_run_id` — i.e. "what this asset looked like last time",
        for the diff engine to compare the current scan's snapshot against.
        """
        result = await self._session.execute(
            select(AssetSnapshot)
            .where(
                AssetSnapshot.asset_id == asset_id,
                AssetSnapshot.scan_run_id != exclude_scan_run_id,
            )
            .order_by(AssetSnapshot.observed_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def for_scan_run(self, scan_run_id: UUID) -> list[AssetSnapshot]:
        result = await self._session.execute(
            select(AssetSnapshot).where(AssetSnapshot.scan_run_id == scan_run_id)
        )
        return list(result.scalars().all())
