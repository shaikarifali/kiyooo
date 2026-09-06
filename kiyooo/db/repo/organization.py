from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from kiyooo.db.models import Organization, OrgRelationship
from kiyooo.db.repo.base import Repository


class OrganizationCreateError(Exception):
    """Raised for a create request this repository refuses outright — never
    silently corrected. See `create`'s third_party guard.
    """


class OrganizationRepository(Repository[Organization]):
    model = Organization

    async def get_by_slug(self, slug: str) -> Organization | None:
        result = await self._session.execute(select(Organization).where(Organization.slug == slug))
        return result.scalar_one_or_none()

    async def create(
        self,
        *,
        slug: str,
        name: str,
        relationship: OrgRelationship,
        parent_org_id: UUID | None,
        legal_entity_name: str | None,
        country: str | None,
        active_scanning_allowed: bool,
        authorization_id: str | None,
        created_by: str,
        created_at: datetime,
    ) -> Organization:
        """`third_party` forces `active_scanning_allowed = False`, mirroring
        `ScopeConfig._third_party_is_always_passive` (config.py) — enforced
        here because an org is created at CLI runtime, not loaded from a
        static file a pydantic validator can gate at parse time.
        """
        if relationship == OrgRelationship.THIRD_PARTY and active_scanning_allowed:
            raise OrganizationCreateError(
                "active_scanning_allowed cannot be true when relationship is third_party — "
                "outward mode is passive-only, structurally, not by policy"
            )
        if await self.get_by_slug(slug) is not None:
            raise OrganizationCreateError(f"an organization with slug {slug!r} already exists")

        org = Organization(
            name=name,
            slug=slug,
            parent_org_id=parent_org_id,
            relationship=relationship,
            legal_entity_name=legal_entity_name,
            country=country,
            active_scanning_allowed=(
                False if relationship == OrgRelationship.THIRD_PARTY else active_scanning_allowed
            ),
            authorization_id=authorization_id,
            created_at=created_at,
            created_by=created_by,
        )
        try:
            return await self.add(org)
        except IntegrityError as exc:
            # The get_by_slug check above is check-then-insert, not
            # atomic — two concurrent `org create acme` calls can both
            # pass it before either commits. `uq_organization_slug` is the
            # real guarantee; this turns its raw IntegrityError into the
            # same clean error the check above already produces, instead
            # of a DB traceback reaching the CLI.
            raise OrganizationCreateError(
                f"an organization with slug {slug!r} already exists"
            ) from exc

    async def list_children(self, parent_org_id: UUID | None) -> list[Organization]:
        """`parent_org_id=None` lists every root org (no parent) — the top
        level of `org list --tree`'s recursion, not "list everything."
        """
        result = await self._session.execute(
            select(Organization).where(Organization.parent_org_id == parent_org_id)
        )
        return list(result.scalars().all())
