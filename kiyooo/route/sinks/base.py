"""Ticket sink protocol. A sink is idempotent from the
caller's side, not its own: `route/pipeline.py` looks up any existing
`Ticket` for a finding before calling `create` vs `reopen` — a sink itself
never has to know whether this is the first time.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Protocol

from kiyooo.db.models import TicketSystem

if TYPE_CHECKING:
    import httpx


@dataclass(frozen=True, slots=True)
class SinkResult:
    external_key: str
    status: str = "open"


class TicketSink(Protocol):
    system: TicketSystem

    async def create(
        self,
        client: httpx.AsyncClient,
        *,
        subject: str,
        body: str,
        assignee: str | None,
        cc: list[str],
        sla_due_at: datetime | None,
    ) -> SinkResult: ...

    async def reopen(
        self, client: httpx.AsyncClient, *, external_key: str, body: str
    ) -> SinkResult: ...
