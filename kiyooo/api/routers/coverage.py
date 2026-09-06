"""GET /api/coverage — Stage 10's coverage stats, backing the
"coverage & orphan-asset report" UI page.
"""

from __future__ import annotations

from fastapi import APIRouter

from kiyooo.api.deps import SessionDep
from kiyooo.api.schemas import CoverageStatsOut
from kiyooo.db.repo.asset import AssetRepository
from kiyooo.db.repo.ownership import OwnershipRepository
from kiyooo.enrich.ownership import merge_existing
from kiyooo.enrich.ownership.merge import MergeOutcome

router = APIRouter()


@router.get("", response_model=CoverageStatsOut)
async def get_coverage(session: SessionDep) -> CoverageStatsOut:
    asset_repo = AssetRepository(session)
    ownership_repo = OwnershipRepository(session)

    assets = await asset_repo.list_all(limit=100_000)
    active_assets = [a for a in assets if a.is_active]

    resolved = disputed = orphan = 0
    high_confidence = 0
    for asset in assets:
        merged = await merge_existing(asset.id, ownership_repo)
        if merged.outcome == MergeOutcome.RESOLVED:
            resolved += 1
        elif merged.outcome == MergeOutcome.DISPUTED:
            disputed += 1
        else:
            orphan += 1
        if merged.top is not None and merged.top.confidence >= 0.8:
            high_confidence += 1

    return CoverageStatsOut(
        total_assets=len(assets),
        active_assets=len(active_assets),
        resolved_ownership=resolved,
        disputed_ownership=disputed,
        orphan_ownership=orphan,
        pct_owner_confidence_gte_0_8=(high_confidence / len(assets)) if assets else 0.0,
    )
