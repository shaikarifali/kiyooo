"""GET /api/attack-paths — Stage 17. Computed on demand each
call (see `graph/attack_path.py`'s docstring for why there's no persisted
table); loads the whole graph/finding set rather than paging, matching
this project's other whole-graph reads (`assets query`, decommission
candidates) — revisit if a real deployment's size makes that too slow.
"""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter

from kiyooo.api.deps import OrgContextDep, SessionDep
from kiyooo.api.schemas import AttackPathHopOut, AttackPathOut
from kiyooo.db.repo.asset import AssetRepository
from kiyooo.db.repo.asset_edge import AssetEdgeRepository
from kiyooo.db.repo.finding import FindingRepository
from kiyooo.graph.attack_path import find_attack_paths

router = APIRouter()

# Whole-graph read, not paged — see module docstring.
_UNBOUNDED = 100_000


@router.get("", response_model=list[AttackPathOut])
async def list_attack_paths(session: SessionDep, org_context: OrgContextDep) -> list[AttackPathOut]:
    sensitive_category_ids = {
        c.id for c in org_context.categories.values() if c.is_sensitive_target
    }
    if not sensitive_category_ids:
        return []

    assets = await AssetRepository(session).list_all(limit=_UNBOUNDED)
    edges = await AssetEdgeRepository(session).list_all(limit=_UNBOUNDED)
    findings = await FindingRepository(session).list_all(limit=_UNBOUNDED)

    paths = find_attack_paths(
        assets, edges, findings, sensitive_category_ids=sensitive_category_ids
    )
    return [
        AttackPathOut(
            hops=[AttackPathHopOut(**asdict(hop)) for hop in path.hops],
            score=path.score,
            sensitive_category_id=path.sensitive_category_id,
        )
        for path in paths
    ]
