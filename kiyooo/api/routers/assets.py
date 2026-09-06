"""GET /api/assets (filter/search), GET /api/assets/{id} — the design
Stage 10. Search reuses `graph/queries.py`'s existing `field=value` filter
language (Stage 2) rather than inventing a second query DSL for the API.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from kiyooo.api.deps import SessionDep
from kiyooo.api.schemas import AssetEdgeOut, AssetOut
from kiyooo.db.repo.asset import AssetRepository
from kiyooo.db.repo.asset_edge import AssetEdgeRepository
from kiyooo.graph.queries import QueryError, query_assets

router = APIRouter()


@router.get("", response_model=list[AssetOut])
async def list_assets(
    session: SessionDep,
    q: list[str] = Query(default=[], description="field=value / field!=value clauses, ANDed"),
) -> list[AssetOut]:
    try:
        assets = await query_assets(session, q)
    except QueryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return [AssetOut.model_validate(a) for a in assets]


@router.get("/{asset_id}", response_model=AssetOut)
async def get_asset(asset_id: UUID, session: SessionDep) -> AssetOut:
    asset = await AssetRepository(session).get(asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="asset not found")
    return AssetOut.model_validate(asset)


@router.get("/{asset_id}/edges", response_model=list[AssetEdgeOut])
async def list_asset_edges(asset_id: UUID, session: SessionDep) -> list[AssetEdgeOut]:
    edges = await AssetEdgeRepository(session).list_for_asset(asset_id)
    return [AssetEdgeOut.model_validate(e) for e in edges]
