"""Email notification sink — stub. No SMTP/provider (SES, SendGrid, ...)
credentials configured in this environment to verify delivery against, so
this raises rather than shipping unverified code, matching every other
no-sandbox integration in this project.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx


@dataclass(slots=True)
class EmailSink:
    smtp_host: str
    from_address: str

    async def send(
        self, client: httpx.AsyncClient, *, to_address: str, subject: str, body: str
    ) -> None:
        raise NotImplementedError(
            "Email sink is unverified — no SMTP/provider credentials configured "
            "to test delivery against. Wire up and add fixture tests before "
            "enabling."
        )
