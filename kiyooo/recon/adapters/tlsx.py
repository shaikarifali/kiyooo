"""tlsx — TLS handshake + certificate probe. Opens a real TLS connection to the
target, so `is_active = True`.
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
class TlsxAdapter(ToolAdapter):
    name = "tlsx"
    binary = "tlsx"
    stage = ReconStage.PROBE
    consumes = {AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP, AssetType.TCP_SERVICE}
    produces = {AssetType.CERT}
    is_active = True

    def _argv(self) -> list[str]:
        return [self.binary or "tlsx", "-silent", "-json", "-cn", "-cert"]

    def describe(self, targets: list[Asset]) -> str:
        return f"{' '.join(self._argv())}  (stdin: {len(targets)} host(s))"

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
        stdin = "\n".join(t.value for t in targets).encode()
        returncode, stdout, stderr = await run_subprocess(self._argv(), stdin=stdin)
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
            host = record.get("host")
            port = record.get("port", "443")
            if not host:
                continue
            evidence.append(
                ParsedEvidence(
                    kind=EvidenceKind.TLS_CERT,
                    asset_type=AssetType.CERT,
                    asset_value=f"{host}:{port}",
                    content=record,
                    collected_at=now,
                )
            )
        return evidence
