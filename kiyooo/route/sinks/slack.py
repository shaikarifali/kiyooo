"""Slack notification sink — real. Used for `notify_channels`, approval-draft
delivery (`ApprovalDraftKind.SLACK`), and the daily digest — never for
filing a ticket-of-record (`TicketSystem` has no Slack value; Slack is a
notify surface, not a system of record). A single incoming-webhook URL
posts to whatever channel that webhook was created for in Slack's UI, so
`channel` here is informational (prefixed into the message) rather than a
per-call routing parameter — a bot-token integration would be needed to
post to an arbitrary channel per call. `build_message` is pure and
fixture-tested; `send` makes the live call and is untested.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx


def build_message(*, channel: str | None, subject: str, body: str) -> dict[str, object]:
    prefix = f"[{channel}] " if channel else ""
    text = f"{prefix}*{subject}*\n{body}" if subject else f"{prefix}{body}"
    return {"text": text}


@dataclass(slots=True)
class SlackSink:
    webhook_url: str

    async def send(
        self, client: httpx.AsyncClient, *, channel: str | None, subject: str, body: str
    ) -> None:
        payload = build_message(channel=channel, subject=subject, body=body)
        resp = await client.post(self.webhook_url, json=payload, timeout=15.0)
        resp.raise_for_status()
