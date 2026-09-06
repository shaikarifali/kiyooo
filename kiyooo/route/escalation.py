"""SLA tracking + escalation: an open ticket whose
`sla_due_at` has passed escalates — notified via the owning team's
`escalation_after_sla` contact, and the ticket moves to `escalated` so a
repeat sweep doesn't re-notify every run. Scheduling this as a daily sweep
is Stage 11; this module is the pure decision logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from kiyooo.db.models import Ticket


@dataclass(frozen=True, slots=True)
class EscalationOutcome:
    to_escalate: list[Ticket]
    still_ok: list[Ticket]


def is_overdue(ticket: Ticket, *, now: datetime) -> bool:
    return ticket.status == "open" and ticket.sla_due_at is not None and ticket.sla_due_at <= now


def sweep_overdue(tickets: list[Ticket], *, now: datetime) -> EscalationOutcome:
    to_escalate = [t for t in tickets if is_overdue(t, now=now)]
    still_ok = [t for t in tickets if not is_overdue(t, now=now)]
    return EscalationOutcome(to_escalate=to_escalate, still_ok=still_ok)
