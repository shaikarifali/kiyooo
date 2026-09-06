"""In-memory fakes for the sibling_asset ownership source, following the
same pattern as tests/graph/fakes.py: Asset and Ownership use Postgres-only
column types, so DB-touching logic is tested against hand-written fakes
matching the real repos' method signatures rather than a live Postgres.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING
from uuid import UUID

from kiyooo.db.models import Asset, Ownership, OwnerType

if TYPE_CHECKING:
    from kiyooo.db.models import OwnershipSource


class FakeAssetRepository:
    def __init__(self, assets: list[Asset] | None = None) -> None:
        self._by_id: dict[UUID, Asset] = {a.id: a for a in (assets or [])}

    async def list_by_value_suffix(self, suffix: str) -> list[Asset]:
        return [a for a in self._by_id.values() if a.value.endswith(suffix)]


class FakeOwnershipRepository:
    def __init__(self) -> None:
        self._by_asset: dict[UUID, list[Ownership]] = {}

    def seed(
        self,
        asset_id: UUID,
        *,
        source: OwnershipSource,
        owner_type: OwnerType = OwnerType.TEAM,
        owner_ref: str = "some-team",
        confidence: float = 1.0,
        verified_by_human: bool = False,
    ) -> Ownership:
        ownership = Ownership(
            id=uuid.uuid4(),
            asset_id=asset_id,
            owner_type=owner_type,
            owner_ref=owner_ref,
            manager_ref=None,
            source=source,
            confidence=confidence,
            evidence_note=None,
            verified_by_human=verified_by_human,
        )
        self._by_asset.setdefault(asset_id, []).append(ownership)
        return ownership

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
        existing_rows = self._by_asset.setdefault(asset_id, [])
        for row in existing_rows:
            if row.source == source:
                row.owner_type = owner_type
                row.owner_ref = owner_ref
                row.manager_ref = manager_ref
                row.confidence = confidence
                row.evidence_note = evidence_note
                row.verified_by_human = verified_by_human
                return row

        ownership = Ownership(
            id=uuid.uuid4(),
            asset_id=asset_id,
            owner_type=owner_type,
            owner_ref=owner_ref,
            manager_ref=manager_ref,
            source=source,
            confidence=confidence,
            evidence_note=evidence_note,
            verified_by_human=verified_by_human,
        )
        existing_rows.append(ownership)
        return ownership

    async def list_for_asset(self, asset_id: UUID) -> list[Ownership]:
        return list(self._by_asset.get(asset_id, []))
