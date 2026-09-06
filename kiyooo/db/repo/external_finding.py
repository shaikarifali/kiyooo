from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select

from kiyooo.db.models import ExternalFindingRaw, ExternalFindingSource, ExternalFindingSystem
from kiyooo.db.repo.base import Repository


class ExternalFindingSourceRepository(Repository[ExternalFindingSource]):
    model = ExternalFindingSource

    async def get_by_system(self, system: ExternalFindingSystem) -> ExternalFindingSource | None:
        result = await self._session.execute(
            select(ExternalFindingSource).where(ExternalFindingSource.system == system)
        )
        return result.scalar_one_or_none()

    async def get_or_create(self, system: ExternalFindingSystem) -> ExternalFindingSource:
        existing = await self.get_by_system(system)
        if existing is not None:
            return existing
        return await self.add(
            ExternalFindingSource(name=system.value, system=system, config={}, enabled=True)
        )

    async def create(
        self, *, name: str, system: ExternalFindingSystem, config: dict[str, object], enabled: bool
    ) -> ExternalFindingSource:
        """Unlike `get_or_create`, always inserts a new row — `CUSTOM`
        sources are identified by id, not by `system`, since an org can
        point kiyooo at more than one REST-emitting tool (or more than
        one tenant of the same tool).
        """
        return await self.add(
            ExternalFindingSource(name=name, system=system, config=config, enabled=enabled)
        )

    async def update_config(
        self, source_id: UUID, *, name: str, config: dict[str, object], enabled: bool
    ) -> ExternalFindingSource:
        source = await self.get(source_id)
        if source is None:
            raise ValueError(f"external_finding_source {source_id} not found")
        source.name = name
        source.config = config
        source.enabled = enabled
        await self._session.flush()
        return source

    async def update_watermark(
        self, source_id: UUID, *, synced_at: datetime, cursor: str | None
    ) -> None:
        source = await self.get(source_id)
        if source is None:
            raise ValueError(f"external_finding_source {source_id} not found")
        source.last_sync_at = synced_at
        source.last_cursor = cursor
        await self._session.flush()


class ExternalFindingRawRepository(Repository[ExternalFindingRaw]):
    model = ExternalFindingRaw

    async def get_by_external_id(
        self, source_id: UUID, external_id: str
    ) -> ExternalFindingRaw | None:
        result = await self._session.execute(
            select(ExternalFindingRaw).where(
                ExternalFindingRaw.source_id == source_id,
                ExternalFindingRaw.external_id == external_id,
            )
        )
        return result.scalar_one_or_none()

    async def upsert(
        self,
        source_id: UUID,
        external_id: str,
        *,
        payload: dict[str, object],
        ingested_at: datetime,
        mapped_finding_id: UUID | None,
        mapping_status: str,
        mapping_notes: str | None,
    ) -> ExternalFindingRaw:
        """`(source_id, external_id)` is the idempotency key (`uq_external_
        finding_source_external_id`) — a re-run of the same vendor export
        updates the existing row rather than duplicating it, which is what
        `openasm ingest --source X --since Y` needs to be safely rerunnable.
        """
        existing = await self.get_by_external_id(source_id, external_id)
        if existing is not None:
            existing.payload = payload
            existing.ingested_at = ingested_at
            existing.mapped_finding_id = mapped_finding_id
            existing.mapping_status = mapping_status
            existing.mapping_notes = mapping_notes
            await self._session.flush()
            return existing

        raw = ExternalFindingRaw(
            source_id=source_id,
            external_id=external_id,
            payload=payload,
            ingested_at=ingested_at,
            mapped_finding_id=mapped_finding_id,
            mapping_status=mapping_status,
            mapping_notes=mapping_notes,
        )
        return await self.add(raw)

    async def list_unmapped(self, source_id: UUID | None = None) -> list[ExternalFindingRaw]:
        stmt = select(ExternalFindingRaw).where(ExternalFindingRaw.mapping_status == "unmapped")
        if source_id is not None:
            stmt = stmt.where(ExternalFindingRaw.source_id == source_id)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())
