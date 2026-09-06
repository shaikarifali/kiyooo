"""GET /api/findings (+verdict+evidence) — Stage 10's change-
feed and triage-queue data source.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from kiyooo.api.deps import SessionDep
from kiyooo.api.schemas import (
    AssetOut,
    EvidenceOut,
    FindingDetailOut,
    FindingOut,
    HumanReviewOut,
    IdentifierVerificationOut,
    VerdictOut,
)
from kiyooo.db.models import FindingStatus
from kiyooo.db.repo.asset import AssetRepository
from kiyooo.db.repo.evidence import EvidenceRepository
from kiyooo.db.repo.finding import FindingRepository
from kiyooo.db.repo.finding_evidence import FindingEvidenceRepository
from kiyooo.db.repo.human_review import HumanReviewRepository
from kiyooo.db.repo.identifier_verification import IdentifierVerificationRepository
from kiyooo.db.repo.verdict import VerdictRepository

router = APIRouter()


@router.get("", response_model=list[FindingOut])
async def list_findings(
    session: SessionDep,
    status: FindingStatus | None = Query(default=None),
    scan_run_id: UUID | None = Query(default=None),
    category_id: str | None = Query(default=None),
    limit: int = Query(default=100, le=1000),
) -> list[FindingOut]:
    findings = await FindingRepository(session).list_filtered(
        status=status, scan_run_id=scan_run_id, category_id=category_id, limit=limit
    )
    return [FindingOut.model_validate(f) for f in findings]


@router.get("/{finding_id}", response_model=FindingDetailOut)
async def get_finding(finding_id: UUID, session: SessionDep) -> FindingDetailOut:
    finding_repo = FindingRepository(session)
    finding = await finding_repo.get(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")

    asset = await AssetRepository(session).get(finding.asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="finding's asset not found")

    verdicts = await VerdictRepository(session).list_for_finding(finding_id)
    latest_verdict = verdicts[-1] if verdicts else None

    links = await FindingEvidenceRepository(session).list_for_finding(finding_id)
    evidence_repo = EvidenceRepository(session)
    evidence_items = []
    for link in links:
        item = await evidence_repo.get(link.evidence_id)
        if item is not None:
            evidence_items.append(item)

    identifier_verifications = await IdentifierVerificationRepository(session).list_for_finding(
        finding_id
    )
    human_reviews = await HumanReviewRepository(session).list_for_finding(finding_id)

    return FindingDetailOut(
        finding=FindingOut.model_validate(finding),
        asset=AssetOut.model_validate(asset),
        latest_verdict=VerdictOut.model_validate(latest_verdict) if latest_verdict else None,
        evidence=[EvidenceOut.model_validate(e) for e in evidence_items],
        identifier_verifications=[
            IdentifierVerificationOut.model_validate(iv) for iv in identifier_verifications
        ],
        human_reviews=[HumanReviewOut.model_validate(hr) for hr in human_reviews],
    )
