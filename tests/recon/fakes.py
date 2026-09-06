"""Fakes for orchestrator tests. Not real `ToolAdapter`/repo implementations —
just enough behavior to drive `Orchestrator` without a subprocess, Postgres,
or MinIO in the loop.

`Orchestrator` reads `consumes`/`stage`/`name` at the *class* level (e.g.
`adapter_cls.consumes`, and it calls `adapter_cls()` with no constructor
args) and reads `is_active`/`stage` again at the *instance* level once
running. `make_fake_adapter_class` builds a fresh class per call with plain
class attributes — mirroring how the real adapters in `kiyooo/recon/adapters/`
are shaped — and configures behavior (raise / fail / return evidence) as
class attributes too, since the orchestrator controls instantiation and a
test can't pass its own constructor kwargs through it.

Persistence-heavy repos (`ScanRunRepository`, `EvidenceWriter`) are faked
here because `Asset`/`Evidence` use Postgres-only column types (JSONB) that
can't be created against SQLite the way `AuditLog` can — see
`tests/recon/conftest.py`'s `audit_log_repo` docstring. `ScopeGuard` itself is
real in these tests; only the DB-writing pieces above/below it are faked.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from kiyooo.recon.base import ParsedEvidence, ReconStage, ToolAdapter, ToolResult

if TYPE_CHECKING:
    from uuid import UUID

    from kiyooo.db.models import Asset, AssetType, ScanRunStatus
    from kiyooo.recon.base import RunContext


class FakeScanRunRepository:
    def __init__(self) -> None:
        self.status_history: list[ScanRunStatus] = []

    async def mark_status(
        self, scan_run_id: UUID, status: ScanRunStatus, *, finished_at: datetime | None = None
    ) -> None:
        self.status_history.append(status)


class FakeEvidenceWriter:
    def __init__(self) -> None:
        self.written: list[tuple[str, list[ParsedEvidence]]] = []

    async def write_many(self, parsed: list[ParsedEvidence], *, source_tool: str) -> list[Asset]:
        self.written.append((source_tool, parsed))
        return []


async def _fake_run(self: ToolAdapter, targets: list[Asset], ctx: RunContext) -> ToolResult:
    self.__class__.run_call_count += 1  # type: ignore[attr-defined]
    self.__class__.received_targets = list(targets)  # type: ignore[attr-defined]
    if self.__class__.should_raise:  # type: ignore[attr-defined]
        raise RuntimeError(f"{self.name} blew up")
    if self.__class__.should_fail:  # type: ignore[attr-defined]
        return ToolResult(
            tool=self.name, stage=self.stage, ok=False, raw_output=b"", error="simulated failure"
        )
    return ToolResult(tool=self.name, stage=self.stage, ok=True, raw_output=b"[]")


def _fake_parse(self: ToolAdapter, raw: bytes) -> list[ParsedEvidence]:
    return self.__class__.evidence_to_return  # type: ignore[attr-defined, no-any-return]


def make_fake_adapter_class(
    name: str,
    stage: ReconStage,
    consumes: set[AssetType],
    *,
    produces: set[AssetType] | None = None,
    is_active: bool = False,
    should_raise: bool = False,
    should_fail: bool = False,
    evidence_to_return: list[ParsedEvidence] | None = None,
) -> type[ToolAdapter]:
    return type(
        f"Fake{name.title()}Adapter",
        (ToolAdapter,),
        {
            "name": name,
            "binary": None,
            "stage": stage,
            "consumes": consumes,
            "produces": produces or set(),
            "is_active": is_active,
            "should_raise": should_raise,
            "should_fail": should_fail,
            "evidence_to_return": evidence_to_return or [],
            "run_call_count": 0,
            "received_targets": [],
            "run": _fake_run,
            "parse": _fake_parse,
        },
    )
