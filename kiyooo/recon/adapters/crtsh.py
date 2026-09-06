"""crt.sh — certificate transparency log lookup. An HTTP call to crt.sh's own
API, never to the target, so `is_active = False`.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx

from kiyooo.db.models import AssetType, EvidenceKind
from kiyooo.recon.base import ParsedEvidence, ReconStage, ToolAdapter, ToolResult
from kiyooo.recon.registry import register

if TYPE_CHECKING:
    from kiyooo.db.models import Asset
    from kiyooo.recon.base import RunContext

_CRTSH_URL = "https://crt.sh/"
_TIMEOUT_S = 30.0


@register
class CrtshAdapter(ToolAdapter):
    name = "crtsh"
    binary = None
    stage = ReconStage.DISCOVER
    consumes = {AssetType.DOMAIN}
    produces = {AssetType.SUBDOMAIN}
    is_active = False

    def describe(self, targets: list[Asset]) -> str:
        domains = ", ".join(t.value for t in targets)
        return f"GET {_CRTSH_URL}?q=%25.<domain>&output=json for [{domains}]"

    async def run(self, targets: list[Asset], ctx: RunContext) -> ToolResult:
        start = time.monotonic()
        records: list[dict[str, object]] = []
        errors: list[str] = []
        async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
            for target in targets:
                await ctx.rate_limiter.acquire("crt.sh")
                try:
                    resp = await client.get(
                        _CRTSH_URL, params={"q": f"%.{target.value}", "output": "json"}
                    )
                    resp.raise_for_status()
                    records.extend(resp.json())
                except (httpx.HTTPError, json.JSONDecodeError) as exc:
                    errors.append(f"{target.value}: {exc}")

        duration_ms = int((time.monotonic() - start) * 1000)
        ok = not errors or bool(records)
        return ToolResult(
            tool=self.name,
            stage=self.stage,
            ok=ok,
            raw_output=json.dumps(records).encode(),
            error="; ".join(errors) if errors and not ok else None,
            duration_ms=duration_ms,
        )

    def parse(self, raw: bytes) -> list[ParsedEvidence]:
        now = datetime.now(UTC)
        try:
            records = json.loads(raw) if raw else []
        except json.JSONDecodeError:
            return []

        evidence: list[ParsedEvidence] = []
        seen: set[str] = set()
        for record in records:
            name_value = record.get("name_value", "")
            for host in name_value.split("\n"):
                host = host.strip().lstrip("*.")
                if not host or host in seen:
                    continue
                seen.add(host)
                evidence.append(
                    ParsedEvidence(
                        kind=EvidenceKind.TLS_CERT,
                        asset_type=AssetType.SUBDOMAIN,
                        asset_value=host,
                        content=record,
                        collected_at=now,
                    )
                )
        return evidence
