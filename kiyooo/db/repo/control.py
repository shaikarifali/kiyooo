from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select

from kiyooo.db.models import Control
from kiyooo.db.repo.base import Repository


class ControlRepository(Repository[Control]):
    model = Control

    async def get_for_asset(self, asset_id: UUID, control_id: str) -> Control | None:
        result = await self._session.execute(
            select(Control).where(Control.asset_id == asset_id, Control.control_id == control_id)
        )
        return result.scalar_one_or_none()

    async def upsert(
        self,
        asset_id: UUID,
        control_id: str,
        *,
        detected_by: str,
        evidence_id: str | None,
        detected_at: datetime,
    ) -> Control:
        """One row per (asset, control_id) — see `Control`'s
        `uq_control_asset_control` constraint. Re-running detection updates
        the existing row rather than accumulating duplicates.
        """
        existing = await self.get_for_asset(asset_id, control_id)
        if existing is not None:
            existing.detected_by = detected_by
            existing.evidence_id = evidence_id
            existing.detected_at = detected_at
            await self._session.flush()
            return existing

        control = Control(
            asset_id=asset_id,
            control_id=control_id,
            detected_by=detected_by,
            evidence_id=evidence_id,
            detected_at=detected_at,
        )
        return await self.add(control)

    async def list_for_asset(self, asset_id: UUID) -> list[Control]:
        result = await self._session.execute(select(Control).where(Control.asset_id == asset_id))
        return list(result.scalars().all())

    async def list_for_assets(self, asset_ids: list[UUID]) -> list[Control]:
        if not asset_ids:
            return []
        result = await self._session.execute(select(Control).where(Control.asset_id.in_(asset_ids)))
        return list(result.scalars().all())
