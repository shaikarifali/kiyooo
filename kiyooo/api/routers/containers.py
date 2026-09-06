"""GET/POST /api/containers/scans — the web UI's Containers page (the design
Stage 14): point kiyooo at a container image or a Kubernetes cluster and run
Trivy (OSS, Apache-2.0) against it. Mirrors `cloud.py`'s account-list/
create/sync shape exactly.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import ValidationError

from kiyooo.api.deps import OrgContextDep, SessionDep
from kiyooo.api.schemas import (
    ContainerScanCreateRequest,
    ContainerScanOut,
    ContainerScanUpdateRequest,
    IngestSyncResultOut,
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
from kiyooo.ingest.adapters.trivy import TrivyRunError
from kiyooo.ingest.sync import sync_trivy_source

router = APIRouter()


@router.get("/scans", response_model=list[ContainerScanOut])
async def list_container_scans(session: SessionDep) -> list[ContainerScanOut]:
    sources = await ExternalFindingSourceRepository(session).list_all()
    scans = [s for s in sources if s.system == ExternalFindingSystem.TRIVY]
    return [ContainerScanOut.model_validate(s) for s in scans]


@router.post("/scans", response_model=ContainerScanOut)
async def create_container_scan(
    body: ContainerScanCreateRequest, session: SessionDep
) -> ContainerScanOut:
    source = await ExternalFindingSourceRepository(session).create(
        name=body.name,
        system=ExternalFindingSystem.TRIVY,
        config=body.config.model_dump(mode="json"),
        enabled=body.enabled,
    )
    return ContainerScanOut.model_validate(source)


@router.put("/scans/{scan_id}", response_model=ContainerScanOut)
async def update_container_scan(
    scan_id: UUID, body: ContainerScanUpdateRequest, session: SessionDep
) -> ContainerScanOut:
    try:
        source = await ExternalFindingSourceRepository(session).update_config(
            scan_id,
            name=body.name,
            config=body.config.model_dump(mode="json"),
            enabled=body.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return ContainerScanOut.model_validate(source)


@router.post("/scans/{scan_id}/sync", response_model=IngestSyncResultOut)
async def sync_container_scan(
    scan_id: UUID, session: SessionDep, org_context: OrgContextDep
) -> IngestSyncResultOut:
    source_repo = ExternalFindingSourceRepository(session)
    source = await source_repo.get(scan_id)
    if source is None or source.system != ExternalFindingSystem.TRIVY:
        raise HTTPException(status_code=404, detail=f"container scan {scan_id} not found")
    if not source.enabled:
        raise HTTPException(status_code=422, detail="scan is disabled")

    try:
        outcome = await sync_trivy_source(
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
    except (ValidationError, ValueError, TrivyRunError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return IngestSyncResultOut(mapped=outcome.mapped, unmapped=outcome.unmapped)
