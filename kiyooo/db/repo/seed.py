from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select

from kiyooo.db.models import ScopeAction, Seed, SeedKind
from kiyooo.db.repo.base import Repository


class SeedRepository(Repository[Seed]):
    model = Seed

    async def create(
        self,
        *,
        org_id: UUID,
        kind: SeedKind,
        value: str,
        scope_action: ScopeAction,
        active_scan_allowed: bool | None,
        note: str | None,
        added_by: str,
        added_at: datetime,
    ) -> Seed:
        seed = Seed(
            org_id=org_id,
            kind=kind,
            value=value,
            scope_action=scope_action,
            active_scan_allowed=active_scan_allowed,
            verified=False,
            note=note,
            added_by=added_by,
            added_at=added_at,
            disabled_at=None,
        )
        return await self.add(seed)

    async def list_for_org(self, org_id: UUID, *, include_disabled: bool = False) -> list[Seed]:
        stmt = select(Seed).where(Seed.org_id == org_id)
        if not include_disabled:
            stmt = stmt.where(Seed.disabled_at.is_(None))
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def disable(self, seed_id: UUID, *, disabled_at: datetime) -> Seed:
        seed = await self.get(seed_id)
        if seed is None:
            raise ValueError(f"seed {seed_id} not found")
        seed.disabled_at = disabled_at
        await self._session.flush()
        return seed
