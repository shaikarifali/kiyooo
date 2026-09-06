from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select

from kiyooo.db.models import Ticket, TicketSystem
from kiyooo.db.repo.base import Repository


class TicketRepository(Repository[Ticket]):
    model = Ticket

    async def get_by_finding(self, finding_id: UUID) -> Ticket | None:
        """A ticket is keyed on `finding_id` (which is itself keyed on the
        finding's fingerprint via `Finding.fingerprint`'s uniqueness) — this
        is the lookup `route/pipeline.py` uses to decide "file a new ticket"
        vs "this finding already has one, reopen/update it instead".
        """
        result = await self._session.execute(select(Ticket).where(Ticket.finding_id == finding_id))
        return result.scalars().first()

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
            finding_id=finding_id,
            system=system,
            external_key=external_key,
            assignee=assignee,
            cc=cc,
            sla_due_at=sla_due_at,
            status=status,
            created_at=created_at,
        )
        return await self.add(ticket)

    async def list_open(self) -> list[Ticket]:
        result = await self._session.execute(
            select(Ticket).where(Ticket.status.in_(["open", "escalated"]))
        )
        return list(result.scalars().all())

    async def set_status(self, ticket_id: UUID, status: str) -> None:
        ticket = await self.get(ticket_id)
        if ticket is None:
            raise ValueError(f"ticket {ticket_id} not found")
        ticket.status = status
        await self._session.flush()
