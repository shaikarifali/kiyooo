"""GET/POST /api/organizations — kiyooo-easm-standalone.md Part D §1's org
model, the web UI's side of `kiyooo org create/list` (Part D §8: same API
the CLI uses, no business logic duplicated in the frontend).
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException

from kiyooo.api.deps import SessionDep
from kiyooo.api.schemas import OrganizationCreateRequest, OrganizationOut
from kiyooo.db.repo.organization import OrganizationCreateError, OrganizationRepository

router = APIRouter()


@router.get("", response_model=list[OrganizationOut])
async def list_organizations(session: SessionDep) -> list[OrganizationOut]:
    orgs = await OrganizationRepository(session).list_all(limit=1000)
    return [OrganizationOut.model_validate(o) for o in orgs]


@router.post("", response_model=OrganizationOut)
async def create_organization(
    body: OrganizationCreateRequest, session: SessionDep
) -> OrganizationOut:
    try:
        org = await OrganizationRepository(session).create(
            slug=body.slug,
            name=body.name,
            relationship=body.relationship,
            parent_org_id=body.parent_org_id,
            legal_entity_name=body.legal_entity_name,
            country=body.country,
            active_scanning_allowed=body.active_scanning_allowed,
            authorization_id=body.authorization_id,
            created_by=body.created_by,
            created_at=datetime.now(UTC),
        )
    except OrganizationCreateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    return OrganizationOut.model_validate(org)
