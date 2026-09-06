"""Fakes for `ingest/pipeline.py` tests — reuses the established fake-repo
pattern from earlier stages.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from kiyooo.db.models import Evidence, ExternalFindingRaw


class FakeEvidenceRepositoryForIngest:
    def __init__(self) -> None:
        self.added: list[Evidence] = []

    async def add(self, evidence: Evidence) -> Evidence:
        self.added.append(evidence)
        return evidence


class FakeExternalFindingRawRepository:
    def __init__(self) -> None:
        self.rows: dict[tuple[UUID, str], ExternalFindingRaw] = {}

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
        row = ExternalFindingRaw(
            source_id=source_id,
            external_id=external_id,
            payload=payload,
            ingested_at=ingested_at,
            mapped_finding_id=mapped_finding_id,
            mapping_status=mapping_status,
            mapping_notes=mapping_notes,
        )
        self.rows[(source_id, external_id)] = row
        return row

    async def list_unmapped(self, source_id: UUID | None = None) -> list[ExternalFindingRaw]:
        rows = list(self.rows.values())
        if source_id is not None:
            rows = [r for r in rows if r.source_id == source_id]
        return [r for r in rows if r.mapping_status == "unmapped"]
