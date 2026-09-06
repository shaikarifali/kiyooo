"""nuclei — template-based scanning. `is_active = True` and the most powerful
tool in the v1 set, which is exactly why CLAUDE.md invariant #1 and the design's
Stage 1 safety requirements single it out by name:

    "nuclei invoked with -etags dos,intrusive,fuzz and a template allowlist"

`_EXCLUDED_TAGS` is always passed, unconditionally — there is no code path in
this adapter that constructs a nuclei command without it. `_ALLOWED_TAGS` is a
conservative default (fingerprinting/misconfig/exposure detection, nothing
that submits credentials, brute-forces a parameter, or fuzzes a path);
surfacing this as org-context config is future work, not Stage 1 — until
then, changing it means changing this file, which is the same review bar as
changing detection logic anywhere else in this codebase.
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

# Never negotiable: invariant #1 (no exploitation primitives — no dos, no
# fuzzing, no intrusive checks) and Stage 1 name these three tags
# explicitly.
_EXCLUDED_TAGS = ("dos", "intrusive", "fuzz")

# Conservative allowlist: fingerprinting and passive-style detection templates
# only. No "cve" wildcard, no "rce", no credential/auth-bypass categories —
# those overlap too much with what invariant #1 forbids to allow-list broadly
# without per-template review this stage doesn't do yet.
_ALLOWED_TAGS = ("tech", "ssl", "dns", "misconfig", "exposure", "panel")


@register
class NucleiAdapter(ToolAdapter):
    name = "nuclei"
    binary = "nuclei"
    stage = ReconStage.SCAN
    consumes = {AssetType.HTTP_SERVICE, AssetType.URL}
    produces: set[AssetType] = set()
    is_active = True

    def _argv(self, targets: list[Asset]) -> list[str]:
        argv = [self.binary or "nuclei", "-silent", "-jsonl"]
        for target in targets:
            argv += ["-target", target.value]
        argv += ["-tags", ",".join(_ALLOWED_TAGS)]
        argv += ["-etags", ",".join(_EXCLUDED_TAGS)]
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
            matched_at = record.get("matched-at") or record.get("host")
            if not matched_at:
                continue
            evidence.append(
                ParsedEvidence(
                    kind=EvidenceKind.NUCLEI_RESULT,
                    asset_type=AssetType.URL,
                    asset_value=matched_at,
                    content=record,
                    collected_at=now,
                )
            )
        return evidence
