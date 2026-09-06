from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from kiyooo.db.models import Ticket, TicketSystem
from kiyooo.route.escalation import is_overdue, sweep_overdue

_NOW = datetime.now(UTC)


def _ticket(*, status: str, sla_due_at: datetime | None) -> Ticket:
    return Ticket(
        id=uuid.uuid4(),
        finding_id=uuid.uuid4(),
        system=TicketSystem.WEBHOOK,
        status=status,
        sla_due_at=sla_due_at,
        created_at=_NOW,
    )


def test_open_ticket_past_due_is_overdue() -> None:
    ticket = _ticket(status="open", sla_due_at=_NOW - timedelta(days=1))
    assert is_overdue(ticket, now=_NOW)


def test_open_ticket_not_yet_due_is_not_overdue() -> None:
    ticket = _ticket(status="open", sla_due_at=_NOW + timedelta(days=1))
    assert not is_overdue(ticket, now=_NOW)


def test_ticket_with_no_sla_is_not_overdue() -> None:
    ticket = _ticket(status="open", sla_due_at=None)
    assert not is_overdue(ticket, now=_NOW)


def test_already_escalated_ticket_is_not_reescalated() -> None:
    ticket = _ticket(status="escalated", sla_due_at=_NOW - timedelta(days=5))
    assert not is_overdue(ticket, now=_NOW)


def test_sweep_partitions_tickets() -> None:
    overdue = _ticket(status="open", sla_due_at=_NOW - timedelta(hours=1))
    fine = _ticket(status="open", sla_due_at=_NOW + timedelta(hours=1))
    outcome = sweep_overdue([overdue, fine], now=_NOW)
    assert outcome.to_escalate == [overdue]
    assert outcome.still_ok == [fine]
