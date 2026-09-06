"""naabu — TCP port scan. Sends SYN/connect probes straight at the target's
own infra, so `is_active = True` — every target here has already cleared
`ScopeGuard`'s active-scan gate before `run()` sees it.
"""

from __future__ import annotations

import json
import shutil
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from kiyooo.db.models import AssetType, EvidenceKind
from kiyooo.recon.adapters._subprocess import run_subprocess
from kiyooo.recon.base import ParsedEvidence, ReconStage, ToolAdapter, ToolResult
from kiyooo.recon.registry import register

if TYPE_CHECKING:
    from kiyooo.db.models import Asset
    from kiyooo.recon.base import RunContext


@register
class NaabuAdapter(ToolAdapter):
    name = "naabu"
    binary = "naabu"
    stage = ReconStage.PORTSCAN
    consumes = {AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP}
    produces = {AssetType.TCP_SERVICE}
    is_active = True

    def _argv(self, targets: list[Asset], ctx: RunContext) -> list[str]:
        rate = str(int(ctx.rate_limiter.requests_per_second * 10))
        argv = [self.binary or "naabu", "-silent", "-json", "-rate", rate]
        for target in targets:
            argv += ["-host", target.value]
        return argv

    def describe(self, targets: list[Asset]) -> str:
        hosts = ", ".join(t.value for t in targets)
        return f"{self.binary} -silent -json -host [{hosts}]"

    async def run(self, targets: list[Asset], ctx: RunContext) -> ToolResult:
        start = time.monotonic()
        if shutil.which(self.binary or "") is None:
            return ToolResult(
                tool=self.name,
                stage=self.stage,
                ok=False,
                raw_output=b"",
                error=f"{self.binary} not found on PATH",
            )
        returncode, stdout, stderr = await run_subprocess(self._argv(targets, ctx))
        duration_ms = int((time.monotonic() - start) * 1000)
        return ToolResult(
            tool=self.name,
            stage=self.stage,
            ok=returncode == 0,
            raw_output=stdout,
            error=None if returncode == 0 else stderr.decode(errors="replace"),
            duration_ms=duration_ms,
        )

    def parse(self, raw: bytes) -> list[ParsedEvidence]:
        now = datetime.now(UTC)
        evidence: list[ParsedEvidence] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = record.get("host") or record.get("ip")
            port = record.get("port")
            if not host or port is None:
                continue
            evidence.append(
                ParsedEvidence(
                    kind=EvidenceKind.PORT_BANNER,
                    asset_type=AssetType.TCP_SERVICE,
                    asset_value=f"{host}:{port}",
                    content=record,
                    collected_at=now,
                )
            )
        return evidence
