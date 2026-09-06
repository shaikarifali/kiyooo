"""Linear ticket sink — stub. Linear's API is GraphQL, not REST, and needs a
real team id / workspace to verify a mutation shape against; no sandbox
here, so this raises rather than shipping unverified code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from kiyooo.db.models import TicketSystem
from kiyooo.route.sinks.base import SinkResult

if TYPE_CHECKING:
    from datetime import datetime

    import httpx


@dataclass(slots=True)
class LinearSink:
    api_key: str
    team_id: str
    system: TicketSystem = TicketSystem.LINEAR

    async def create(
        self,
        client: httpx.AsyncClient,
        *,
        subject: str,
        body: str,
        assignee: str | None,
        cc: list[str],
        sla_due_at: datetime | None,
    ) -> SinkResult:
        raise NotImplementedError(
            "Linear sink is unverified — GraphQL mutation shape needs a real "
            "workspace/team id to test against. Wire up and add fixture tests "
            "before enabling."
        )

    async def reopen(
        self, client: httpx.AsyncClient, *, external_key: str, body: str
    ) -> SinkResult:
        raise NotImplementedError("see create()")
