"""ServiceNow ticket sink — stub. Table API field names (`short_description`
vs `description`, incident vs custom table) vary per-instance customization;
no sandbox instance here to verify against, so this raises rather than
shipping unverified code.
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
class ServiceNowSink:
    instance_url: str
    username: str
    password: str
    table: str = "incident"
    system: TicketSystem = TicketSystem.SERVICENOW

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
            "ServiceNow sink is unverified — Table API field names vary by "
            "instance customization; no sandbox to test against. Wire up and "
            "add fixture tests before enabling."
        )

    async def reopen(
        self, client: httpx.AsyncClient, *, external_key: str, body: str
    ) -> SinkResult:
        raise NotImplementedError("see create()")
