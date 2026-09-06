"""Generic-webhook ticket sink — real and the "no vendor tenant to verify
against" pick (same role CSV played for Stage 1b's importers): any org
running a custom ITSM relay can point this at their own endpoint.
`build_payload` is pure and fixture-tested; `create`/`reopen` make the live
call and are untested, same treatment as every other network-touching
function in this project.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from kiyooo.db.models import TicketSystem
from kiyooo.route.sinks.base import SinkResult

if TYPE_CHECKING:
    import httpx


def build_payload(
    *,
    action: str,
    subject: str | None,
    body: str,
    assignee: str | None,
    cc: list[str],
    sla_due_at: datetime | None,
    external_key: str | None,
) -> dict[str, object]:
    return {
        "action": action,
        "subject": subject,
        "body": body,
        "assignee": assignee,
        "cc": cc,
        "sla_due_at": sla_due_at.isoformat() if sla_due_at else None,
        "external_key": external_key,
    }


@dataclass(slots=True)
class WebhookSink:
    url: str
    system: TicketSystem = TicketSystem.WEBHOOK

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
        payload = build_payload(
            action="create",
            subject=subject,
            body=body,
            assignee=assignee,
            cc=cc,
            sla_due_at=sla_due_at,
            external_key=None,
        )
        resp = await client.post(self.url, json=payload, timeout=30.0)
        resp.raise_for_status()
        data = resp.json()
        external_key = str(data.get("id") or data.get("external_key") or subject)
        return SinkResult(external_key=external_key, status="open")

    async def reopen(
        self, client: httpx.AsyncClient, *, external_key: str, body: str
    ) -> SinkResult:
        payload = build_payload(
            action="reopen",
            subject=None,
            body=body,
            assignee=None,
            cc=[],
            sla_due_at=None,
            external_key=external_key,
        )
        resp = await client.post(self.url, json=payload, timeout=30.0)
        resp.raise_for_status()
        return SinkResult(external_key=external_key, status="open")
