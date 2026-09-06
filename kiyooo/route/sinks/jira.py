"""Jira ticket sink — stub. Jira Cloud's REST API needs a project key, an
issue-type mapping, and an API token scoped to a real site; there's no
sandbox tenant in this environment to verify field names or auth flow
against, so this raises rather than shipping best-effort-and-unverified
code, matching the treatment `ingest/adapters/qualys.py` etc. gave every
other no-sandbox integration.
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
class JiraSink:
    base_url: str
    api_token: str
    project_key: str
    system: TicketSystem = TicketSystem.JIRA

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
            "Jira sink is unverified — no sandbox tenant to test field names or "
            "auth against. Wire this up against your own Jira Cloud site and add "
            "fixture tests before enabling."
        )

    async def reopen(
        self, client: httpx.AsyncClient, *, external_key: str, body: str
    ) -> SinkResult:
        raise NotImplementedError("see create()")
