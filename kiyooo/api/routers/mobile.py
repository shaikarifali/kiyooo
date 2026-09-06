"""GET/POST /api/mobile/scans — the web UI's Mobile page (the design
Stage 16): point kiyooo at a local APK file and statically analyze it
(apktool + reused TruffleHog filesystem scan). Mirrors the other
domain-expansion routers' list/create/sync shape exactly.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import ValidationError

from kiyooo.api.deps import OrgContextDep, SessionDep
from kiyooo.api.schemas import (
    IngestSyncResultOut,
    MobileScanCreateRequest,
    MobileScanOut,
    MobileScanUpdateRequest,
)
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
from kiyooo.ingest.adapters.mobile_static import MobileScanError
from kiyooo.ingest.adapters.trufflehog import TrufflehogRunError
from kiyooo.ingest.sync import sync_mobile_static_source

router = APIRouter()


@router.get("/scans", response_model=list[MobileScanOut])
async def list_mobile_scans(session: SessionDep) -> list[MobileScanOut]:
    sources = await ExternalFindingSourceRepository(session).list_all()
    scans = [s for s in sources if s.system == ExternalFindingSystem.MOBILE_STATIC]
    return [MobileScanOut.model_validate(s) for s in scans]


@router.post("/scans", response_model=MobileScanOut)
async def create_mobile_scan(body: MobileScanCreateRequest, session: SessionDep) -> MobileScanOut:
    source = await ExternalFindingSourceRepository(session).create(
        name=body.name,
        system=ExternalFindingSystem.MOBILE_STATIC,
        config=body.config.model_dump(mode="json"),
        enabled=body.enabled,
    )
    return MobileScanOut.model_validate(source)


@router.put("/scans/{scan_id}", response_model=MobileScanOut)
async def update_mobile_scan(
    scan_id: UUID, body: MobileScanUpdateRequest, session: SessionDep
) -> MobileScanOut:
    try:
        source = await ExternalFindingSourceRepository(session).update_config(
            scan_id,
            name=body.name,
            config=body.config.model_dump(mode="json"),
            enabled=body.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return MobileScanOut.model_validate(source)


@router.post("/scans/{scan_id}/sync", response_model=IngestSyncResultOut)
async def sync_mobile_scan(
    scan_id: UUID, session: SessionDep, org_context: OrgContextDep
) -> IngestSyncResultOut:
    source_repo = ExternalFindingSourceRepository(session)
    source = await source_repo.get(scan_id)
    if source is None or source.system != ExternalFindingSystem.MOBILE_STATIC:
        raise HTTPException(status_code=404, detail=f"mobile scan {scan_id} not found")
    if not source.enabled:
        raise HTTPException(status_code=422, detail="scan is disabled")

    try:
        outcome = await sync_mobile_static_source(
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
    except (ValidationError, ValueError, MobileScanError, TrufflehogRunError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return IngestSyncResultOut(mapped=outcome.mapped, unmapped=outcome.unmapped)
