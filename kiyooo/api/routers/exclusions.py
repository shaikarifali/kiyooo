"""GET/POST /api/exclusions — the web UI's side of `kiyooo exclusion
add/list`. Same repository calls the CLI uses (Part D §8's parity rule).
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Query

from kiyooo.api.deps import SessionDep
from kiyooo.api.schemas import ExclusionCreateRequest, ExclusionOut
from kiyooo.db.repo.exclusion import ExclusionRepository

router = APIRouter()


@router.get("", response_model=list[ExclusionOut])
async def list_exclusions(
    session: SessionDep, org_id: UUID | None = Query(default=None)
) -> list[ExclusionOut]:
    repo = ExclusionRepository(session)
    rows = await (repo.list_global() if org_id is None else repo.list_for_org_and_global(org_id))
    return [ExclusionOut.model_validate(r) for r in rows]


@router.post("", response_model=ExclusionOut)
async def create_exclusion(body: ExclusionCreateRequest, session: SessionDep) -> ExclusionOut:
    excl = await ExclusionRepository(session).create(
        org_id=body.org_id,
        kind=body.kind,
        value=body.value,
        reason=body.reason,
        source=body.source,
        created_at=datetime.now(UTC),
    )
    return ExclusionOut.model_validate(excl)
