from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import or_, select

from kiyooo.db.models import AssetEdge, AssetEdgeRelation
from kiyooo.db.repo.base import Repository


class AssetEdgeRepository(Repository[AssetEdge]):
    model = AssetEdge

    async def list_for_asset(self, asset_id: UUID) -> list[AssetEdge]:
        """Stage 10's asset-explorer "graph view" — every edge touching
        this asset on either side, since a relation can point either way
        (`resolves_to`, `hosted_on`, ...).
        """
        result = await self._session.execute(
            select(AssetEdge).where(
                or_(AssetEdge.src_asset_id == asset_id, AssetEdge.dst_asset_id == asset_id)
            )
        )
        return list(result.scalars().all())

    async def get_existing(
        self, src_asset_id: UUID, dst_asset_id: UUID, relation: AssetEdgeRelation
    ) -> AssetEdge | None:
        result = await self._session.execute(
            select(AssetEdge).where(
                AssetEdge.src_asset_id == src_asset_id,
                AssetEdge.dst_asset_id == dst_asset_id,
                AssetEdge.relation == relation,
            )
        )
        return result.scalar_one_or_none()

    async def get_or_create(
        self,
        src_asset_id: UUID,
        dst_asset_id: UUID,
        relation: AssetEdgeRelation,
        *,
        confidence: float,
        discovered_by: str,
    ) -> AssetEdge:
        existing = await self.get_existing(src_asset_id, dst_asset_id, relation)
        now = datetime.now(UTC)
        if existing is not None:
            existing.last_seen = now
            existing.confidence = max(existing.confidence, confidence)
            await self._session.flush()
            return existing

        edge = AssetEdge(
            src_asset_id=src_asset_id,
            dst_asset_id=dst_asset_id,
            relation=relation,
            confidence=confidence,
            discovered_by=discovered_by,
            first_seen=now,
            last_seen=now,
        )
        return await self.add(edge)
