from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import or_, select

from kiyooo.db.models import Exclusion, ExclusionSource, SeedKind
from kiyooo.db.repo.base import Repository


class ExclusionRepository(Repository[Exclusion]):
    model = Exclusion

    async def create(
        self,
        *,
        org_id: UUID | None,
        kind: SeedKind,
        value: str,
        reason: str,
        source: ExclusionSource,
        created_at: datetime,
    ) -> Exclusion:
        exclusion = Exclusion(
            org_id=org_id,
            kind=kind,
            value=value,
            reason=reason,
            source=source,
            created_at=created_at,
        )
        return await self.add(exclusion)

    async def list_for_org_and_global(self, org_id: UUID) -> list[Exclusion]:
        """Every exclusion that applies when scanning `org_id`: that org's
        own rows, plus every global default (`org_id IS NULL`) — global
        exclusions always apply on top of an org's own, never instead of.
        """
        result = await self._session.execute(
            select(Exclusion).where(or_(Exclusion.org_id == org_id, Exclusion.org_id.is_(None)))
        )
        return list(result.scalars().all())

    async def list_global(self) -> list[Exclusion]:
        result = await self._session.execute(select(Exclusion).where(Exclusion.org_id.is_(None)))
        return list(result.scalars().all())
