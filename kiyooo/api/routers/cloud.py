"""GET/POST /api/cloud/accounts — the web UI's Cloud page (the design
Stage 13): point kiyooo at an AWS/Azure/GCP/Kubernetes account and run
Prowler (OSS, Apache-2.0) against it. Mirrors `ingest.py`'s source-list/
create/sync shape exactly (Part D §8 parity: CLI and API share this
module's functions, never duplicate the logic).
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import ValidationError

from kiyooo.api.deps import OrgContextDep, SessionDep
from kiyooo.api.schemas import (
    CloudAccountCreateRequest,
    CloudAccountOut,
    CloudAccountUpdateRequest,
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
from kiyooo.ingest.adapters.prowler import ProwlerRunError
from kiyooo.ingest.sync import sync_prowler_source

router = APIRouter()


@router.get("/accounts", response_model=list[CloudAccountOut])
async def list_cloud_accounts(session: SessionDep) -> list[CloudAccountOut]:
    sources = await ExternalFindingSourceRepository(session).list_all()
    accounts = [s for s in sources if s.system == ExternalFindingSystem.PROWLER]
    return [CloudAccountOut.model_validate(a) for a in accounts]


@router.post("/accounts", response_model=CloudAccountOut)
async def create_cloud_account(
    body: CloudAccountCreateRequest, session: SessionDep
) -> CloudAccountOut:
    source = await ExternalFindingSourceRepository(session).create(
        name=body.name,
        system=ExternalFindingSystem.PROWLER,
        config=body.config.model_dump(mode="json"),
        enabled=body.enabled,
    )
    return CloudAccountOut.model_validate(source)


@router.put("/accounts/{account_id}", response_model=CloudAccountOut)
async def update_cloud_account(
    account_id: UUID, body: CloudAccountUpdateRequest, session: SessionDep
) -> CloudAccountOut:
    try:
        source = await ExternalFindingSourceRepository(session).update_config(
            account_id,
            name=body.name,
            config=body.config.model_dump(mode="json"),
            enabled=body.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return CloudAccountOut.model_validate(source)


@router.post("/accounts/{account_id}/sync", response_model=IngestSyncResultOut)
async def sync_cloud_account(
    account_id: UUID, session: SessionDep, org_context: OrgContextDep
) -> IngestSyncResultOut:
    source_repo = ExternalFindingSourceRepository(session)
    source = await source_repo.get(account_id)
    if source is None or source.system != ExternalFindingSystem.PROWLER:
        raise HTTPException(status_code=404, detail=f"cloud account {account_id} not found")
    if not source.enabled:
        raise HTTPException(status_code=422, detail="account is disabled")

    try:
        outcome = await sync_prowler_source(
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
    except (ValidationError, ValueError, ProwlerRunError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return IngestSyncResultOut(mapped=outcome.mapped, unmapped=outcome.unmapped)
