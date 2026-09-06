"""amass enum -passive — passive subdomain enumeration. The design's v1 set names
this tool explicitly as "amass(passive)": active enumeration (brute force,
zone transfer attempts) is a different, more intrusive subcommand this
adapter never invokes.

amass only writes JSON to a file (`-json <path>`), not stdout, so `run()`
uses a temp file and reads it back into `raw_output` — every other adapter
here captures stdout directly.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from kiyooo.db.models import AssetType, EvidenceKind
from kiyooo.recon.adapters._subprocess import run_subprocess
from kiyooo.recon.base import ParsedEvidence, ReconStage, ToolAdapter, ToolResult
from kiyooo.recon.registry import register

if TYPE_CHECKING:
    from kiyooo.db.models import Asset
    from kiyooo.recon.base import RunContext


@register
class AmassAdapter(ToolAdapter):
    name = "amass"
    binary = "amass"
    stage = ReconStage.DISCOVER
    consumes = {AssetType.DOMAIN}
    produces = {AssetType.SUBDOMAIN}
    is_active = False

    def _argv(self, targets: list[Asset], out_path: str) -> list[str]:
        argv = [self.binary or "amass", "enum", "-passive", "-json", out_path]
        for target in targets:
            argv += ["-d", target.value]
        return argv

    def describe(self, targets: list[Asset]) -> str:
        return " ".join(self._argv(targets, "<tmpfile>"))

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
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path = tmp.name
        try:
            returncode, _stdout, stderr = await run_subprocess(self._argv(targets, out_path))
            raw_output = (
                await asyncio.to_thread(Path(out_path).read_bytes) if returncode == 0 else b""
            )
        finally:
            await asyncio.to_thread(Path(out_path).unlink, missing_ok=True)

        duration_ms = int((time.monotonic() - start) * 1000)
        return ToolResult(
            tool=self.name,
            stage=self.stage,
            ok=returncode == 0,
            raw_output=raw_output,
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
            name = record.get("name")
            if not name:
                continue
            evidence.append(
                ParsedEvidence(
                    kind=EvidenceKind.DNS_RECORD,
                    asset_type=AssetType.SUBDOMAIN,
                    asset_value=name,
                    content=record,
                    collected_at=now,
                )
            )
        return evidence
