"""Shodan host lookup — queries Shodan's own database about an IP, never the
IP itself, so `is_active = False`. Requires `SHODAN_API_KEY`; without it this
adapter fails cleanly (`ToolResult(ok=False, ...)`) rather than crashing the
run — the orchestrator's partial-failure tolerance covers "adapter not
configured" the same as "adapter timed out".
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

_SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
_TIMEOUT_S = 30.0


@register
class ShodanAdapter(ToolAdapter):
    name = "shodan"
    binary = None
    stage = ReconStage.DISCOVER
    consumes = {AssetType.IP}
    produces = {AssetType.TCP_SERVICE, AssetType.HTTP_SERVICE}
    is_active = False

    def describe(self, targets: list[Asset]) -> str:
        ips = ", ".join(t.value for t in targets)
        return f"GET {_SHODAN_HOST_URL.format(ip='<ip>')} for [{ips}]"

    async def run(self, targets: list[Asset], ctx: RunContext) -> ToolResult:
        start = time.monotonic()
        api_key = os.environ.get("SHODAN_API_KEY")
        if not api_key:
            return ToolResult(
                tool=self.name,
                stage=self.stage,
                ok=False,
                raw_output=b"",
                error="SHODAN_API_KEY not set",
            )

        records: list[dict[str, object]] = []
        errors: list[str] = []
        async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
            for target in targets:
                await ctx.rate_limiter.acquire("api.shodan.io")
                try:
                    resp = await client.get(
                        _SHODAN_HOST_URL.format(ip=target.value), params={"key": api_key}
                    )
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
        for host_record in records:
            ip = host_record.get("ip_str")
            if not ip:
                continue
            for service in host_record.get("data", []):
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
