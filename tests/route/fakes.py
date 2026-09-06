"""In-memory fakes for `route/` tests — same pattern as `tests/detect/fakes.py`
and `tests/graph/fakes.py`: hand-written fakes matching the real repos'
method signatures, since Finding/Verdict/Ticket/Approval all use
Postgres-only column types.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from kiyooo.db.models import Approval, ApprovalStatus, Finding, FindingStatus, Ticket

if TYPE_CHECKING:
    from kiyooo.db.models import ApprovalDraftKind, TicketSystem, Verdict


class FakeFindingRepositoryForRoute:
    def __init__(self, findings: list[Finding] | None = None) -> None:
        self._by_id: dict[UUID, Finding] = {f.id: f for f in (findings or [])}

    async def get(self, id_: UUID) -> Finding | None:
        return self._by_id.get(id_)

    async def mark_status(self, finding_id: UUID, status: FindingStatus) -> None:
        finding = self._by_id[finding_id]
        finding.status = status

    async def list_for_scan_run_by_status(
        self, scan_run_id: UUID, status: FindingStatus
    ) -> list[Finding]:
        return [
            f for f in self._by_id.values() if f.scan_run_id == scan_run_id and f.status == status
        ]

    async def list_by_status(self, status: FindingStatus) -> list[Finding]:
        return [f for f in self._by_id.values() if f.status == status]

    async def list_by_status_since(self, status: FindingStatus, cutoff: datetime) -> list[Finding]:
        return [f for f in self._by_id.values() if f.status == status and f.first_seen >= cutoff]


class FakeVerdictRepository:
    def __init__(self) -> None:
        self._by_finding: dict[UUID, list[Verdict]] = {}

    def seed(self, finding_id: UUID, verdict: Verdict) -> None:
        self._by_finding.setdefault(finding_id, []).append(verdict)

    async def list_for_finding(self, finding_id: UUID) -> list[Verdict]:
        return list(self._by_finding.get(finding_id, []))


class FakeTicketRepository:
    def __init__(self) -> None:
        self._by_id: dict[UUID, Ticket] = {}
        self._by_finding: dict[UUID, UUID] = {}

    async def get(self, id_: UUID) -> Ticket | None:
        return self._by_id.get(id_)

    async def get_by_finding(self, finding_id: UUID) -> Ticket | None:
        ticket_id = self._by_finding.get(finding_id)
        return self._by_id.get(ticket_id) if ticket_id else None

    async def create(
        self,
        *,
        finding_id: UUID,
        system: TicketSystem,
        external_key: str | None,
        assignee: str | None,
        cc: list[str],
        sla_due_at: datetime | None,
        status: str,
        created_at: datetime,
    ) -> Ticket:
        ticket = Ticket(
            id=uuid.uuid4(),
            finding_id=finding_id,
            system=system,
            external_key=external_key,
            assignee=assignee,
            cc=cc,
            sla_due_at=sla_due_at,
            status=status,
            created_at=created_at,
        )
        self._by_id[ticket.id] = ticket
        self._by_finding[finding_id] = ticket.id
        return ticket

    async def list_open(self) -> list[Ticket]:
        return [t for t in self._by_id.values() if t.status in ("open", "escalated")]

    async def set_status(self, ticket_id: UUID, status: str) -> None:
        self._by_id[ticket_id].status = status


class FakeApprovalRepository:
    def __init__(self) -> None:
        self._by_id: dict[UUID, Approval] = {}

    async def get(self, id_: UUID) -> Approval | None:
        return self._by_id.get(id_)

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
            id=uuid.uuid4(),
            finding_id=finding_id,
            draft_kind=draft_kind,
            rendered_body=rendered_body,
            rendered_subject=rendered_subject,
            target_assignee=target_assignee,
            target_cc=target_cc,
            status=ApprovalStatus.PENDING,
        )
        self._by_id[approval.id] = approval
        return approval

    async def list_pending(self) -> list[Approval]:
        return [a for a in self._by_id.values() if a.status == ApprovalStatus.PENDING]
