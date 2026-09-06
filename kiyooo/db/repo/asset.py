from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from kiyooo.db.models import Asset, AssetType
from kiyooo.db.repo.base import Repository


class AssetRepository(Repository[Asset]):
    model = Asset

    async def get_by_identity(self, type_: AssetType, value: str) -> Asset | None:
        result = await self._session.execute(
            select(Asset).where(Asset.type == type_, Asset.value == value)
        )
        return result.scalar_one_or_none()

    async def get_by_value(self, value: str) -> Asset | None:
        """Look up an asset by value alone, ignoring type. Used by edge
        derivation (`normalize/parsers/`), which knows a related value from
        evidence content (e.g. a hostname or IP string) but not which
        `AssetType` it was originally upserted under. Safe in practice: a
        canonicalized value is only ever created under one type, since
        `get_or_create` resolves identity as `(type, value)` and nothing else
        in this codebase re-upserts the same string under a second type.
        """
        result = await self._session.execute(select(Asset).where(Asset.value == value).limit(1))
        return result.scalar_one_or_none()

    async def get_or_create(
        self,
        type_: AssetType,
        value: str,
        *,
        confidence_in_scope: float,
        scope_reason: str | None = None,
    ) -> Asset:
        """Asset identity is `UNIQUE(type, value)` — a rescan that finds the same
        asset again must update `last_seen`, not insert a duplicate row. If the
        asset had decayed to `is_active = False` (see `graph.builder.decay_
        inactive_assets`), being seen again reactivates it — decay only means
        "not seen recently," not "gone for good."
        """
        existing = await self.get_by_identity(type_, value)
        now = datetime.now(UTC)
        if existing is not None:
            existing.last_seen = now
            existing.is_active = True
            await self._session.flush()
            return existing

        asset = Asset(
            type=type_,
            value=value,
            first_seen=now,
            last_seen=now,
            is_active=True,
            confidence_in_scope=confidence_in_scope,
            scope_reason=scope_reason,
            attributes={},
        )
        return await self.add(asset)

    async def list_by_value_suffix(self, suffix: str) -> list[Asset]:
        """Used by the sibling-asset ownership source to
        find other hostnames under the same parent domain, e.g.
        `suffix=".example.com"` matches `api.example.com`.
        """
        result = await self._session.execute(select(Asset).where(Asset.value.like(f"%{suffix}")))
        return list(result.scalars().all())

    async def list_active_last_seen_before(self, cutoff: datetime) -> list[Asset]:
        result = await self._session.execute(
            select(Asset).where(Asset.is_active.is_(True), Asset.last_seen < cutoff)
        )
        return list(result.scalars().all())

    async def list_active(self) -> list[Asset]:
        result = await self._session.execute(select(Asset).where(Asset.is_active.is_(True)))
        return list(result.scalars().all())

    async def mark_inactive(self, assets: list[Asset]) -> None:
        for asset in assets:
            asset.is_active = False
        if assets:
            await self._session.flush()
