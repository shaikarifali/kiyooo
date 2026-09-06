"""GET/POST /api/assets/{id}/ownership — Stage 10's "ownership
override" deliverable, and Stage 7's "confirm or reassign in one click"
UI action for a low-confidence attribution shown on a ticket. A POST here
writes a `MANUAL` ownership candidate exactly like `ownership_
overrides.yaml` does (Stage 3: "a human states the answer directly, so it
always wins") — same source, same confidence=1.0, same
`verified_by_human=True` — just written at request time through the API
instead of at config-load time through git.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException

from kiyooo.api.deps import SessionDep
from kiyooo.api.schemas import OwnershipOut, OwnershipOverrideRequest
from kiyooo.db.models import OwnershipSource
from kiyooo.db.repo.asset import AssetRepository
from kiyooo.db.repo.ownership import OwnershipRepository
from kiyooo.enrich.ownership import merge_existing

router = APIRouter()


@router.get("/assets/{asset_id}/ownership", response_model=OwnershipOut | None)
async def get_ownership(asset_id: UUID, session: SessionDep) -> OwnershipOut | None:
    merged = await merge_existing(asset_id, OwnershipRepository(session))
    if merged.top is None:
        return None
    return OwnershipOut(
        owner_type=merged.top.owner_type,
        owner_ref=merged.top.owner_ref,
        source=merged.top.source.value,
        confidence=merged.top.confidence,
        note=merged.top.evidence_note,
    )


@router.post("/assets/{asset_id}/ownership", response_model=OwnershipOut)
async def override_ownership(
    asset_id: UUID, body: OwnershipOverrideRequest, session: SessionDep
) -> OwnershipOut:
    asset = await AssetRepository(session).get(asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="asset not found")

    note = (
        f"{body.note} (via API, by {body.reviewer})"
        if body.note
        else f"via API, by {body.reviewer}"
    )
    ownership = await OwnershipRepository(session).upsert_candidate(
        asset_id,
        OwnershipSource.MANUAL,
        owner_type=body.owner_type,
        owner_ref=body.owner_ref,
        confidence=1.0,
        evidence_note=note,
        verified_by_human=True,
    )
    return OwnershipOut(
        owner_type=ownership.owner_type,
        owner_ref=ownership.owner_ref,
        source=ownership.source.value,
        confidence=ownership.confidence,
        note=ownership.evidence_note,
    )
