from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from kiyooo.db.models import FindingEvidence, FindingEvidenceRole
from kiyooo.db.repo.base import Repository


class FindingEvidenceRepository(Repository[FindingEvidence]):
    model = FindingEvidence

    async def link(self, finding_id: UUID, evidence_id: str, role: FindingEvidenceRole) -> None:
        """`(finding_id, evidence_id)` is the table's composite primary key
        — re-running detection against unchanged evidence must not raise a
        duplicate-key error, so this updates the existing link's role
        rather than inserting blind.
        """
        result = await self._session.execute(
            select(FindingEvidence).where(
                FindingEvidence.finding_id == finding_id,
                FindingEvidence.evidence_id == evidence_id,
            )
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            existing.role = role
            await self._session.flush()
            return

        self._session.add(
            FindingEvidence(finding_id=finding_id, evidence_id=evidence_id, role=role)
        )
        await self._session.flush()

    async def list_for_finding(self, finding_id: UUID) -> list[FindingEvidence]:
        result = await self._session.execute(
            select(FindingEvidence).where(FindingEvidence.finding_id == finding_id)
        )
        return list(result.scalars().all())
