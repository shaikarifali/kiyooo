"""Censys host lookup — queries Censys's own database about an IP, never the
IP itself, so `is_active = False`. Requires `CENSYS_API_ID` /
`CENSYS_API_SECRET`; missing credentials fail this adapter cleanly rather
than crash the run, same as `shodan.py`.
"""

from __future__ import annotations

import json
import os
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

_CENSYS_HOST_URL = "https://search.censys.io/api/v2/hosts/{ip}"
_TIMEOUT_S = 30.0


@register
class CensysAdapter(ToolAdapter):
    name = "censys"
    binary = None
    stage = ReconStage.DISCOVER
    consumes = {AssetType.IP}
    produces = {AssetType.TCP_SERVICE, AssetType.HTTP_SERVICE}
    is_active = False

    def describe(self, targets: list[Asset]) -> str:
        ips = ", ".join(t.value for t in targets)
        return f"GET {_CENSYS_HOST_URL.format(ip='<ip>')} for [{ips}]"

    async def run(self, targets: list[Asset], ctx: RunContext) -> ToolResult:
        start = time.monotonic()
        api_id = os.environ.get("CENSYS_API_ID")
        api_secret = os.environ.get("CENSYS_API_SECRET")
        if not api_id or not api_secret:
            return ToolResult(
                tool=self.name,
                stage=self.stage,
                ok=False,
                raw_output=b"",
                error="CENSYS_API_ID / CENSYS_API_SECRET not set",
            )

        records: list[dict[str, object]] = []
        errors: list[str] = []
        auth = httpx.BasicAuth(api_id, api_secret)
        async with httpx.AsyncClient(timeout=_TIMEOUT_S, auth=auth) as client:
            for target in targets:
                await ctx.rate_limiter.acquire("search.censys.io")
                try:
                    resp = await client.get(_CENSYS_HOST_URL.format(ip=target.value))
                    resp.raise_for_status()
                    records.append(resp.json())
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
        for wrapper in records:
            result = wrapper.get("result", {})
            ip = result.get("ip")
            if not ip:
                continue
            for service in result.get("services", []):
                port = service.get("port")
                if port is None:
                    continue
                evidence.append(
                    ParsedEvidence(
                        kind=EvidenceKind.PORT_BANNER,
                        asset_type=AssetType.TCP_SERVICE,
                        asset_value=f"{ip}:{port}",
                        content=service,
                        collected_at=now,
                    )
                )
        return evidence
