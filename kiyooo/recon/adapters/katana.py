"""katana — web crawler. Fetches pages from the target's live site, so
`is_active = True`.
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
class KatanaAdapter(ToolAdapter):
    name = "katana"
    binary = "katana"
    stage = ReconStage.CRAWL
    consumes = {AssetType.HTTP_SERVICE}
    produces = {AssetType.URL}
    is_active = True

    def _argv(self, targets: list[Asset]) -> list[str]:
        argv = [self.binary or "katana", "-silent", "-jsonl"]
        for target in targets:
            argv += ["-u", target.value]
        return argv

    def describe(self, targets: list[Asset]) -> str:
        return " ".join(self._argv(targets))

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
        returncode, stdout, stderr = await run_subprocess(self._argv(targets))
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
            endpoint = record.get("request", {}).get("endpoint")
            if not endpoint:
                continue
            evidence.append(
                ParsedEvidence(
                    kind=EvidenceKind.HTTP_RESPONSE,
                    asset_type=AssetType.URL,
                    asset_value=endpoint,
                    content=record,
                    collected_at=now,
                )
            )
        return evidence
