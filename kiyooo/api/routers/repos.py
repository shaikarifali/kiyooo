"""GET/POST /api/repos/scans — the web UI's Repos page:
point kiyooo at a git repo and scan it for verified live secrets with
TruffleHog (OSS engine, AGPL-3.0). Mirrors `cloud.py`/`containers.py`'s
list/create/sync shape exactly.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import ValidationError

from kiyooo.api.deps import OrgContextDep, SessionDep
from kiyooo.api.schemas import (
    IngestSyncResultOut,
    RepoScanCreateRequest,
    RepoScanOut,
    RepoScanUpdateRequest,
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
from kiyooo.ingest.adapters.trufflehog import TrufflehogRunError
from kiyooo.ingest.sync import sync_trufflehog_source

router = APIRouter()


@router.get("/scans", response_model=list[RepoScanOut])
async def list_repo_scans(session: SessionDep) -> list[RepoScanOut]:
    sources = await ExternalFindingSourceRepository(session).list_all()
    scans = [s for s in sources if s.system == ExternalFindingSystem.TRUFFLEHOG]
    return [RepoScanOut.model_validate(s) for s in scans]


@router.post("/scans", response_model=RepoScanOut)
async def create_repo_scan(body: RepoScanCreateRequest, session: SessionDep) -> RepoScanOut:
    source = await ExternalFindingSourceRepository(session).create(
        name=body.name,
        system=ExternalFindingSystem.TRUFFLEHOG,
        config=body.config.model_dump(mode="json"),
        enabled=body.enabled,
    )
    return RepoScanOut.model_validate(source)


@router.put("/scans/{scan_id}", response_model=RepoScanOut)
async def update_repo_scan(
    scan_id: UUID, body: RepoScanUpdateRequest, session: SessionDep
) -> RepoScanOut:
    try:
        source = await ExternalFindingSourceRepository(session).update_config(
            scan_id,
            name=body.name,
            config=body.config.model_dump(mode="json"),
            enabled=body.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return RepoScanOut.model_validate(source)


@router.post("/scans/{scan_id}/sync", response_model=IngestSyncResultOut)
async def sync_repo_scan(
    scan_id: UUID, session: SessionDep, org_context: OrgContextDep
) -> IngestSyncResultOut:
    source_repo = ExternalFindingSourceRepository(session)
    source = await source_repo.get(scan_id)
    if source is None or source.system != ExternalFindingSystem.TRUFFLEHOG:
        raise HTTPException(status_code=404, detail=f"repo scan {scan_id} not found")
    if not source.enabled:
        raise HTTPException(status_code=422, detail="scan is disabled")

    try:
        outcome = await sync_trufflehog_source(
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
    except (ValidationError, ValueError, TrufflehogRunError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return IngestSyncResultOut(mapped=outcome.mapped, unmapped=outcome.unmapped)
