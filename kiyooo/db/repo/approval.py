from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select

from kiyooo.db.models import Approval, ApprovalDraftKind, ApprovalStatus
from kiyooo.db.repo.base import Repository


class ApprovalRepository(Repository[Approval]):
    model = Approval

    async def create(
        self,
        *,
        finding_id: UUID,
        draft_kind: ApprovalDraftKind,
        rendered_body: str,
        rendered_subject: str | None,
        target_assignee: str | None,
        target_cc: list[str],
    ) -> Approval:
        approval = Approval(
            finding_id=finding_id,
            draft_kind=draft_kind,
            rendered_body=rendered_body,
            rendered_subject=rendered_subject,
            target_assignee=target_assignee,
            target_cc=target_cc,
            status=ApprovalStatus.PENDING,
        )
        return await self.add(approval)

    async def list_pending(self) -> list[Approval]:
        result = await self._session.execute(
            select(Approval).where(Approval.status == ApprovalStatus.PENDING)
        )
        return list(result.scalars().all())

    async def decide(
        self,
        approval_id: UUID,
        *,
        status: ApprovalStatus,
        reviewer: str,
        reviewed_at: datetime,
        edit_diff: str | None = None,
    ) -> Approval:
        approval = await self.get(approval_id)
        if approval is None:
            raise ValueError(f"approval {approval_id} not found")
        approval.status = status
        approval.reviewer = reviewer
        approval.reviewed_at = reviewed_at
        approval.edit_diff = edit_diff
        await self._session.flush()
        return approval

    async def mark_sent(self, approval_id: UUID, *, sent_at: datetime, external_key: str) -> None:
        approval = await self.get(approval_id)
        if approval is None:
            raise ValueError(f"approval {approval_id} not found")
        approval.sent_at = sent_at
        approval.external_key = external_key
        await self._session.flush()
