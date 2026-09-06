"""GET/POST /api/ingest/sources — the web UI's Ingest page: point kiyooo
at any REST/JSON-emitting ASM/VM tool (Stage 1b, "or any
other") without a code change. `system` is always `CUSTOM` here — the
two hand-written adapters (Mandiant/Tenable) stay CLI/`.env`-only, this
endpoint is for the generic, config-driven connector
(`ingest/adapters/generic_rest.py`). Mirrors `kiyooo ingest sources
add/list` / `kiyooo ingest run --source <id>` exactly (Part D §8 parity).
"""

from __future__ import annotations

from uuid import UUID

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import ValidationError

from kiyooo.api.deps import OrgContextDep, SessionDep
from kiyooo.api.schemas import (
    IngestSourceCreateRequest,
    IngestSourceOut,
    IngestSourceUpdateRequest,
    IngestSyncResultOut,
    IngestTestResultOut,
    UnmappedFindingOut,
)
from kiyooo.config import OrgContext
from kiyooo.db.models import ExternalFindingSystem
from kiyooo.db.repo.asset import AssetRepository
from kiyooo.db.repo.evidence import EvidenceRepository
from kiyooo.db.repo.external_finding import (
    ExternalFindingRawRepository,
    ExternalFindingSourceRepository,
)
from kiyooo.db.repo.finding import FindingRepository
from kiyooo.db.repo.finding_evidence import FindingEvidenceRepository
from kiyooo.db.repo.scan_run import ScanRunRepository
from kiyooo.ingest.adapters.generic_rest import GenericRestConfig, fetch_items, parse_item
from kiyooo.ingest.mapper import map_category
from kiyooo.ingest.sync import sync_generic_source
from kiyooo.llm.credentials import resolve_credential
from kiyooo.llm.provider import ProviderError

router = APIRouter()


def _would_map(vendor_issue_type: str, asset_type_value: str, org_context: OrgContext) -> bool:
    """Mirrors `ingest/pipeline.py::ingest_finding`'s own mapped/unmapped
    decision exactly (category exists, is enabled, and applies to this
    asset type) — a preview that skipped any of these would tell a user
    "would map" for an item that a real sync would actually leave
    unmapped, which is worse than no preview at all.
    """
    category_id = map_category(vendor_issue_type, org_context.vendor_mapping)
    category = org_context.categories.get(category_id) if category_id else None
    return category is not None and category.enabled and asset_type_value in category.applies_to


@router.post("/test", response_model=IngestTestResultOut)
async def test_ingest_source(
    body: GenericRestConfig, org_context: OrgContextDep
) -> IngestTestResultOut:
    try:
        credential = resolve_credential(body.credential_ref)
        async with httpx.AsyncClient() as client:
            raw_items = await fetch_items(client, body, credential=credential)
        imported = [parse_item(item, body) for item in raw_items]
    except (ValueError, ProviderError, httpx.HTTPError) as exc:
        return IngestTestResultOut(
            ok=False,
            item_count=0,
            mapped_preview=0,
            unmapped_preview=0,
            sample_titles=[],
            error=str(exc),
        )

    mapped = sum(
        1
        for f in imported
        if _would_map(f.vendor_issue_type, body.default_asset_type.value, org_context)
    )
    return IngestTestResultOut(
        ok=True,
        item_count=len(imported),
        mapped_preview=mapped,
        unmapped_preview=len(imported) - mapped,
        sample_titles=[f.title for f in imported[:5]],
        error=None,
    )


@router.get("/sources", response_model=list[IngestSourceOut])
async def list_ingest_sources(session: SessionDep) -> list[IngestSourceOut]:
    """Only sources with a valid `GenericRestConfig` — a bare `system=
    CUSTOM` row with `config={}` also gets auto-created as a watermark
    placeholder by the older `kiyooo ingest run --file --format csv`
    path (unrelated to this connector), and would otherwise show up here
    as an unusable, unsyncable card.
    """
    sources = await ExternalFindingSourceRepository(session).list_all()
    configured = []
    for s in sources:
        try:
            GenericRestConfig.model_validate(s.config)
        except ValidationError:
            continue
        configured.append(s)
    return [IngestSourceOut.model_validate(s) for s in configured]


@router.post("/sources", response_model=IngestSourceOut)
async def create_ingest_source(
    body: IngestSourceCreateRequest, session: SessionDep
) -> IngestSourceOut:
    source = await ExternalFindingSourceRepository(session).create(
        name=body.name,
        system=ExternalFindingSystem.CUSTOM,
        config=body.config.model_dump(mode="json"),
        enabled=body.enabled,
    )
    return IngestSourceOut.model_validate(source)


@router.put("/sources/{source_id}", response_model=IngestSourceOut)
async def update_ingest_source(
    source_id: UUID, body: IngestSourceUpdateRequest, session: SessionDep
) -> IngestSourceOut:
    try:
        source = await ExternalFindingSourceRepository(session).update_config(
            source_id,
            name=body.name,
            config=body.config.model_dump(mode="json"),
            enabled=body.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return IngestSourceOut.model_validate(source)


@router.post("/sources/{source_id}/sync", response_model=IngestSyncResultOut)
async def sync_ingest_source(
    source_id: UUID, session: SessionDep, org_context: OrgContextDep
) -> IngestSyncResultOut:
    source_repo = ExternalFindingSourceRepository(session)
    source = await source_repo.get(source_id)
    if source is None:
        raise HTTPException(status_code=404, detail=f"ingest source {source_id} not found")
    if not source.enabled:
        raise HTTPException(status_code=422, detail="source is disabled")

    try:
        outcome = await sync_generic_source(
            source,
            org_context=org_context,
            asset_repo=AssetRepository(session),
            evidence_repo=EvidenceRepository(session),
            finding_repo=FindingRepository(session),
            finding_evidence_repo=FindingEvidenceRepository(session),
            external_finding_repo=ExternalFindingRawRepository(session),
            source_repo=source_repo,
            scan_run_repo=ScanRunRepository(session),
        )
    except (ValidationError, ValueError, ProviderError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return IngestSyncResultOut(mapped=outcome.mapped, unmapped=outcome.unmapped)


@router.get("/unmapped", response_model=list[UnmappedFindingOut])
async def list_unmapped_findings(
    session: SessionDep, source_id: UUID | None = None
) -> list[UnmappedFindingOut]:
    """Includes each row's source `name` directly — a client would
    otherwise have to cross-reference `GET /sources`, which only lists
    sources with a valid `GenericRestConfig` and would leave rows from
    any other source (a hand-written adapter, a one-off file import)
    unresolvable.
    """
    source_repo = ExternalFindingSourceRepository(session)
    rows = await ExternalFindingRawRepository(session).list_unmapped(source_id)
    names: dict[UUID, str] = {}
    out = []
    for row in rows:
        if row.source_id not in names:
            source = await source_repo.get(row.source_id)
            names[row.source_id] = source.name if source is not None else str(row.source_id)
        out.append(
            UnmappedFindingOut(
                id=row.id,
                source_id=row.source_id,
                source_name=names[row.source_id],
                external_id=row.external_id,
                mapping_notes=row.mapping_notes,
                ingested_at=row.ingested_at,
            )
        )
    return out
