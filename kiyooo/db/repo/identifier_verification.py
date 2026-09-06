from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from kiyooo.db.models import IdentifierVerification
from kiyooo.db.repo.base import Repository


class IdentifierVerificationRepository(Repository[IdentifierVerification]):
    model = IdentifierVerification

    async def list_for_finding(self, finding_id: UUID) -> list[IdentifierVerification]:
        result = await self._session.execute(
            select(IdentifierVerification).where(IdentifierVerification.finding_id == finding_id)
        )
        return list(result.scalars().all())
