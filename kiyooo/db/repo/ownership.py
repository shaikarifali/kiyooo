from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from kiyooo.db.models import Ownership, OwnershipSource, OwnerType
from kiyooo.db.repo.base import Repository


class OwnershipRepository(Repository[Ownership]):
    model = Ownership

    async def get_by_source(self, asset_id: UUID, source: OwnershipSource) -> Ownership | None:
        result = await self._session.execute(
            select(Ownership).where(Ownership.asset_id == asset_id, Ownership.source == source)
        )
        return result.scalar_one_or_none()

    async def upsert_candidate(
        self,
        asset_id: UUID,
        source: OwnershipSource,
        *,
        owner_type: OwnerType,
        owner_ref: str,
        confidence: float,
        manager_ref: str | None = None,
        evidence_note: str | None = None,
        verified_by_human: bool = False,
    ) -> Ownership:
        """One candidate row per (asset, source) — see `Ownership`'s
        `uq_ownership_asset_source` constraint. Re-running enrichment updates
        the existing candidate for that source rather than accumulating
        duplicates.
        """
        existing = await self.get_by_source(asset_id, source)
        if existing is not None:
            existing.owner_type = owner_type
            existing.owner_ref = owner_ref
            existing.manager_ref = manager_ref
            existing.confidence = confidence
            existing.evidence_note = evidence_note
            existing.verified_by_human = verified_by_human
            await self._session.flush()
            return existing

        ownership = Ownership(
            asset_id=asset_id,
            owner_type=owner_type,
            owner_ref=owner_ref,
            manager_ref=manager_ref,
            source=source,
            confidence=confidence,
            evidence_note=evidence_note,
            verified_by_human=verified_by_human,
        )
        return await self.add(ownership)

    async def list_for_asset(self, asset_id: UUID) -> list[Ownership]:
        result = await self._session.execute(
            select(Ownership).where(Ownership.asset_id == asset_id)
        )
        return list(result.scalars().all())
