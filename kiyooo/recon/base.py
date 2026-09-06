"""ToolAdapter ABC — the contract every recon tool wrapper implements (the design,
Stage 1). `orchestrator.py` drives instances of this; `adapters/*.py` implement it.

Two things are deliberately NOT part of this contract:

- **Network access.** An adapter's `run()` must ask `ctx.scope_guard` before it
  sends anything to a target. `run()` never touches the network directly for a
  target it hasn't cleared — that's invariant #2, enforced here at the point
  every adapter is required to go through, not trusted to remember.
- **Evidence persistence.** `parse()` returns `ParsedEvidence` — plain data, not
  a persisted `Evidence` row. Assigning the human-readable `ev_<scan>_<n>` id,
  hashing content, and writing to Postgres/MinIO is the evidence writer's job
  (`orchestrator.py`), not the adapter's. This keeps a parser testable against a
  recorded fixture with no DB or object store in the loop.
"""

from __future__ import annotations

import asyncio
import enum
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from kiyooo.db.models import AssetType, EvidenceKind

if TYPE_CHECKING:
    import structlog

    from kiyooo.db.models import Asset
    from kiyooo.recon.scope import ScopeGuard


class ReconStage(enum.StrEnum):
    """Stage 1: DISCOVER|RESOLVE|PORTSCAN|PROBE|CRAWL|SCAN."""

    DISCOVER = "discover"
    RESOLVE = "resolve"
    PORTSCAN = "portscan"
    PROBE = "probe"
    CRAWL = "crawl"
    SCAN = "scan"


class ScanProfile(enum.StrEnum):
    """`kiyooo scan --profile`. Each profile is a fixed set of stages, chosen so
    that going from passive -> standard -> deep is a strictly increasing amount
    of contact with the target, never a different kind of contact.
    """

    PASSIVE = "passive"
    STANDARD = "standard"
    DEEP = "deep"


@dataclass(frozen=True, slots=True)
class ParsedEvidence:
    """What an adapter's `parse()` extracts from one raw tool output, before the
    evidence writer turns it into a persisted `Evidence` row.
    """

    kind: EvidenceKind
    asset_type: AssetType
    asset_value: str
    content: dict[str, object]
    collected_at: datetime


@dataclass(frozen=True, slots=True)
class ToolResult:
    tool: str
    stage: ReconStage
    ok: bool
    raw_output: bytes
    error: str | None = None
    duration_ms: int = 0


class HostRateLimiter:
    """Requests-per-second cap per target host, enforced centrally (the design
    Stage 1 safety requirements) — one shared instance per scan run, not a
    per-tool setting.

    Subprocess-wrapped adapters (subfinder, naabu, httpx, ...) can't be paced
    packet-by-packet from Python since the binary owns its own connections;
    for those, the same `requests_per_second` value is passed as a CLI rate
    flag instead (an adapter concern, not this class's). This limiter is for
    adapters that call out over HTTP directly from Python (shodan, censys,
    crtsh) and can genuinely await between requests to the same host.
    """

    def __init__(self, requests_per_second: float) -> None:
        self.requests_per_second = requests_per_second
        self._min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0.0
        self._last_request_at: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, host: str) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = (self._last_request_at.get(host, 0.0) + self._min_interval) - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_at[host] = time.monotonic()


@dataclass(frozen=True, slots=True)
class RunContext:
    """Everything an adapter needs to run one stage of one scan, and nothing it
    needs to reach for outside this object — no adapter should import Settings
    or open its own DB session.
    """

    scan_run_id: UUID
    scope_guard: ScopeGuard
    profile: ScanProfile
    dry_run: bool
    logger: structlog.stdlib.BoundLogger
    rate_limiter: HostRateLimiter = field(default_factory=lambda: HostRateLimiter(5.0))


class ToolAdapter(ABC):
    name: str
    binary: str | None
    stage: ReconStage
    consumes: set[AssetType]
    produces: set[AssetType]
    is_active: bool  # sends packets directly to the target's own infra?

    @abstractmethod
    async def run(self, targets: list[Asset], ctx: RunContext) -> ToolResult: ...

    @abstractmethod
    def parse(self, raw: bytes) -> list[ParsedEvidence]: ...

    def describe(self, targets: list[Asset]) -> str:
        """Human-readable stand-in for the real command line, used by
        `--dry-run` (nothing runs, this is all that's shown) and `--explain`.
        Subprocess-backed adapters override this with their actual argv; the
        default here is only good enough for adapters that call an HTTP API
        directly and have no argv to show.
        """
        return f"{self.name} <{len(targets)} target(s)>"
