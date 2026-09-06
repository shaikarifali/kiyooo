"""GitHub Issues ticket sink — real, well-documented public REST API shape
(same rationale Stage 1b used for Tenable). `build_create_payload` is pure
and fixture-tested; `create`/`reopen` make the live call and are untested.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from kiyooo.db.models import TicketSystem
from kiyooo.route.sinks.base import SinkResult

if TYPE_CHECKING:
    from datetime import datetime

    import httpx

_API_BASE = "https://api.github.com"


def build_create_payload(*, subject: str, body: str, assignee: str | None) -> dict[str, object]:
    payload: dict[str, object] = {"title": subject, "body": body}
    if assignee:
        payload["assignees"] = [assignee]
    return payload


@dataclass(slots=True)
class GithubSink:
    token: str
    repo: str  # "owner/repo"
    system: TicketSystem = TicketSystem.GITHUB

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
        }

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
        payload = build_create_payload(subject=subject, body=body, assignee=assignee)
        resp = await client.post(
            f"{_API_BASE}/repos/{self.repo}/issues",
            json=payload,
            headers=self._headers(),
            timeout=30.0,
        )
        resp.raise_for_status()
        data = resp.json()
        return SinkResult(external_key=str(data["number"]), status="open")

    async def reopen(
        self, client: httpx.AsyncClient, *, external_key: str, body: str
    ) -> SinkResult:
        resp = await client.patch(
            f"{_API_BASE}/repos/{self.repo}/issues/{external_key}",
            json={"state": "open", "body": body},
            headers=self._headers(),
            timeout=30.0,
        )
        resp.raise_for_status()
        return SinkResult(external_key=external_key, status="open")
