"""GET/POST /api/seeds — the web UI's side of `kiyooo seed add/list/disable`.
Same repository calls the CLI uses (Part D §8's parity rule).
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from kiyooo.api.deps import SessionDep
from kiyooo.api.schemas import SeedCreateRequest, SeedOut
from kiyooo.db.repo.seed import SeedRepository

router = APIRouter()


@router.get("", response_model=list[SeedOut])
async def list_seeds(
    session: SessionDep,
    org_id: UUID = Query(...),
    include_disabled: bool = Query(default=False),
) -> list[SeedOut]:
    seeds = await SeedRepository(session).list_for_org(org_id, include_disabled=include_disabled)
    return [SeedOut.model_validate(s) for s in seeds]


@router.post("", response_model=SeedOut)
async def create_seed(body: SeedCreateRequest, session: SessionDep) -> SeedOut:
    seed = await SeedRepository(session).create(
        org_id=body.org_id,
        kind=body.kind,
        value=body.value,
        scope_action=body.scope_action,
        active_scan_allowed=body.active_scan_allowed,
        note=body.note,
        added_by=body.added_by,
        added_at=datetime.now(UTC),
    )
    return SeedOut.model_validate(seed)


@router.post("/{seed_id}/disable", response_model=SeedOut)
async def disable_seed(seed_id: UUID, session: SessionDep) -> SeedOut:
    try:
        seed = await SeedRepository(session).disable(seed_id, disabled_at=datetime.now(UTC))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    return SeedOut.model_validate(seed)
