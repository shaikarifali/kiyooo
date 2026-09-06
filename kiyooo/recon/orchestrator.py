"""Stage DAG + evidence writer.

Runs every registered adapter for the current profile, in `_STAGE_ORDER`,
feeding each stage's discovered assets forward as the next stage's targets.
Two things are load-bearing here, not incidental:

- **ScopeGuard runs per target, per adapter, every time** — never once at scan
  start. An asset discovered mid-run (e.g. a subdomain `subfinder` finds) gets
  the same check as a seed. This is invariant #2 in practice, not just in
  `scope.py`.
- **One adapter's failure — timeout, exception, non-zero exit — never stops
  the run.** `_run_adapter` catches everything around a single adapter's
  `run()` call and returns a failed `AdapterOutcome` instead of propagating;
  `run()`'s stage loop uses `gather(..., return_exceptions=True)` as a second
  layer in case a bug in this file itself, not the adapter, is what breaks.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

import structlog
from minio.error import S3Error

from kiyooo.db.models import Asset, AssetType, Evidence, ScanRunStatus
from kiyooo.db.repo.asset import AssetRepository
from kiyooo.db.repo.asset_edge import AssetEdgeRepository
from kiyooo.db.repo.evidence import EvidenceRepository
from kiyooo.db.repo.scan_run import ScanRunRepository
from kiyooo.graph.builder import upsert_asset
from kiyooo.normalize.injection import scan_evidence_content
from kiyooo.normalize.parsers import derive_edges
from kiyooo.normalize.redact import redact_content
from kiyooo.recon import registry
from kiyooo.recon.base import HostRateLimiter, ParsedEvidence, ReconStage, RunContext, ToolAdapter
from kiyooo.recon.scope import ScopeGuard

if TYPE_CHECKING:
    from minio import Minio

    from kiyooo.recon.base import ScanProfile

_logger = structlog.get_logger()

_STAGE_ORDER: tuple[ReconStage, ...] = (
    ReconStage.DISCOVER,
    ReconStage.RESOLVE,
    ReconStage.PORTSCAN,
    ReconStage.PROBE,
    ReconStage.CRAWL,
    ReconStage.SCAN,
)

DEFAULT_PER_TOOL_TIMEOUT_S = 120.0
DEFAULT_MAX_RETRIES = 2
DEFAULT_BACKOFF_BASE_S = 2.0
DEFAULT_MAX_CONCURRENCY_PER_STAGE = 4
DEFAULT_RATE_LIMIT_RPS = 5.0

# Evidence at or under this size lives inline as JSONB; larger payloads go to
# the object store and only their key + hash live in Postgres.
_INLINE_THRESHOLD_BYTES = 4096


class EvidenceWriter:
    """Turns an adapter's `ParsedEvidence` into a persisted `Evidence` row plus
    the `Asset` row it belongs to ("raw stdout -> S3/MinIO, metadata
    row -> Postgres, content hash for dedupe").

    Storage is content-addressed (`cas/<sha256>.json`): an unchanged rescan
    that re-produces byte-identical raw output reuses the existing object
    instead of re-uploading it. This is the "content hash for dedupe" the design doc
    asks for — it dedupes *storage*, not evidence rows; every scan still gets
    its own `Evidence` row tied to its own `scan_run_id`, because "identical to
    last time" is itself something Stage 2's diff engine needs to see.

    One `EvidenceWriter` is shared by every adapter in a scan run, and the
    orchestrator runs multiple adapters concurrently within a stage — same
    constraint as `ScopeGuard`: the underlying `AsyncSession` can't take
    concurrent writes from two adapters finishing at once, so `write_many`
    serializes on `_lock`. MinIO's `put_object`/`stat_object` calls don't
    touch the session and could in principle run outside the lock, but the
    real cost here is adapter `run()` time, not this — not worth the added
    complexity of a finer-grained lock.
    """

    def __init__(
        self,
        *,
        evidence_repo: EvidenceRepository,
        asset_repo: AssetRepository,
        asset_edge_repo: AssetEdgeRepository,
        minio_client: Minio,
        bucket: str,
        scan_run_id: UUID,
    ) -> None:
        self._evidence_repo = evidence_repo
        self._asset_repo = asset_repo
        self._asset_edge_repo = asset_edge_repo
        self._minio = minio_client
        self._bucket = bucket
        self._scan_run_id = scan_run_id
        self._counter = 0
        self._lock = asyncio.Lock()

    async def write_many(self, parsed: list[ParsedEvidence], *, source_tool: str) -> list[Asset]:
        async with self._lock:
            return [await self._write_one(item, source_tool=source_tool) for item in parsed]

    async def _write_one(self, item: ParsedEvidence, *, source_tool: str) -> Asset:
        asset = await upsert_asset(
            self._asset_repo, item.asset_type, item.asset_value, confidence_in_scope=1.0
        )
        await self._write_edges(asset, item, source_tool=source_tool)

        self._counter += 1
        evidence_id = f"ev_{self._scan_run_id}_{self._counter}"

        # Invariant #7: redact before hashing/storing, never after — a
        # secret must never reach content_hash, object storage, or logs.
        redacted_content, secrets_found = redact_content(item.content)
        if secrets_found:
            redacted_content = {
                **redacted_content,
                "_redacted_secrets": [
                    {"secret_type": s.secret_type, "partial_hash": s.partial_hash}
                    for s in secrets_found
                ],
            }

        raw_bytes = json.dumps(redacted_content, sort_keys=True, default=str).encode("utf-8")
        content_hash = hashlib.sha256(raw_bytes).hexdigest()

        content_ref: str | None = None
        content_inline: dict[str, object] | None = None
        if len(raw_bytes) <= _INLINE_THRESHOLD_BYTES:
            content_inline = redacted_content
        else:
            content_ref = await self._put_object(content_hash, raw_bytes)

        evidence = Evidence(
            id=evidence_id,
            scan_run_id=self._scan_run_id,
            asset_id=asset.id,
            kind=item.kind,
            source_tool=source_tool,
            collected_at=item.collected_at,
            content_ref=content_ref,
            content_inline=content_inline,
            content_hash=content_hash,
            size_bytes=len(raw_bytes),
            redacted=bool(secrets_found),
            # the design — scanned before storage, not at triage time,
            # so the flag is a durable property of the evidence row itself.
            injection_suspected=scan_evidence_content(redacted_content),
        )
        await self._evidence_repo.add(evidence)
        return asset

    async def _write_edges(self, asset: Asset, item: ParsedEvidence, *, source_tool: str) -> None:
        for hint in derive_edges(source_tool, item):
            related = await self._asset_repo.get_by_value(hint.related_asset_value)
            if related is None:
                # The related asset isn't in the graph (yet, or ever) — an edge
                # needs two real asset ids, so there's nothing to create.
                continue
            src, dst = (asset, related) if hint.own_is_src else (related, asset)
            await self._asset_edge_repo.get_or_create(
                src.id,
                dst.id,
                hint.relation,
                confidence=hint.confidence,
                discovered_by=source_tool,
            )

    async def _put_object(self, content_hash: str, raw_bytes: bytes) -> str:
        key = f"cas/{content_hash}.json"
        if not await asyncio.to_thread(self._object_exists, key):
            await asyncio.to_thread(
                self._minio.put_object,
                self._bucket,
                key,
                io.BytesIO(raw_bytes),
                len(raw_bytes),
                content_type="application/json",
            )
        return key

    def _object_exists(self, key: str) -> bool:
        try:
            self._minio.stat_object(self._bucket, key)
        except S3Error:
            return False
        return True


@dataclass(slots=True)
class AdapterOutcome:
    tool: str
    stage: ReconStage
    ok: bool
    evidence_count: int = 0
    error: str | None = None
    dry_run: bool = False
    description: str | None = None
    allowed_targets: int = 0
    denied_targets: int = 0
    discovered_assets: list[Asset] = field(default_factory=list)


class Orchestrator:
    def __init__(
        self,
        *,
        scan_run_repo: ScanRunRepository,
        evidence_writer: EvidenceWriter,
        scope_guard: ScopeGuard,
        profile: ScanProfile,
        dry_run: bool,
        logger: structlog.stdlib.BoundLogger,
        max_concurrency_per_stage: int = DEFAULT_MAX_CONCURRENCY_PER_STAGE,
        per_tool_timeout_s: float = DEFAULT_PER_TOOL_TIMEOUT_S,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_base_s: float = DEFAULT_BACKOFF_BASE_S,
        rate_limit_rps: float = DEFAULT_RATE_LIMIT_RPS,
        adapter_classes: list[type[ToolAdapter]] | None = None,
    ) -> None:
        """`adapter_classes`, if given, replaces the real adapter registry —
        this is what lets tests drive `Orchestrator` with fake adapters
        without importing (and thereby registering, and risking invoking)
        every real subprocess/HTTP-backed adapter kiyooo ships. `None` (the
        default, and what the CLI passes) means "use every real adapter."
        """
        self._scan_run_repo = scan_run_repo
        self._evidence_writer = evidence_writer
        self._scope_guard = scope_guard
        self._profile = profile
        self._dry_run = dry_run
        self._logger = logger
        self._max_concurrency_per_stage = max_concurrency_per_stage
        self._per_tool_timeout_s = per_tool_timeout_s
        self._max_retries = max_retries
        self._backoff_base_s = backoff_base_s
        self._rate_limiter = HostRateLimiter(rate_limit_rps)
        self._adapter_classes = adapter_classes

    def _all_adapter_classes(self) -> list[type[ToolAdapter]]:
        if self._adapter_classes is not None:
            return self._adapter_classes
        import kiyooo.recon.adapters  # noqa: F401  # registers every real adapter on import

        return registry.all_adapters()

    async def run(self, seeds: list[Asset], scan_run_id: UUID) -> list[AdapterOutcome]:
        all_adapters = self._all_adapter_classes()

        ctx = RunContext(
            scan_run_id=scan_run_id,
            scope_guard=self._scope_guard,
            profile=self._profile,
            dry_run=self._dry_run,
            logger=self._logger,
            rate_limiter=self._rate_limiter,
        )

        await self._scan_run_repo.mark_status(scan_run_id, ScanRunStatus.RUNNING)

        pool: dict[tuple[AssetType, str], Asset] = {(a.type, a.value): a for a in seeds}
        outcomes: list[AdapterOutcome] = []
        stages = registry.stages_for_profile(self._profile)

        for stage in _STAGE_ORDER:
            if stage not in stages:
                continue
            adapters = [cls for cls in all_adapters if cls.stage == stage]
            if not adapters:
                continue

            sem = asyncio.Semaphore(self._max_concurrency_per_stage)
            tasks = [self._run_adapter(cls, list(pool.values()), ctx, sem) for cls in adapters]
            stage_results = await asyncio.gather(*tasks, return_exceptions=True)

            for cls, stage_result in zip(adapters, stage_results, strict=True):
                if isinstance(stage_result, BaseException):
                    self._logger.error(
                        "orchestrator.adapter_crashed", tool=cls.name, error=str(stage_result)
                    )
                    outcomes.append(
                        AdapterOutcome(
                            tool=cls.name, stage=stage, ok=False, error=str(stage_result)
                        )
                    )
                    continue
                outcomes.append(stage_result)
                for asset in stage_result.discovered_assets:
                    pool[(asset.type, asset.value)] = asset

        await self._scan_run_repo.mark_status(
            scan_run_id, ScanRunStatus.COMPLETED, finished_at=datetime.now(UTC)
        )
        return outcomes

    async def _run_adapter(
        self,
        adapter_cls: type[ToolAdapter],
        pool: list[Asset],
        ctx: RunContext,
        sem: asyncio.Semaphore,
    ) -> AdapterOutcome:
        adapter = adapter_cls()
        candidates = [a for a in pool if a.type in adapter_cls.consumes]

        if ctx.dry_run:
            description = adapter.describe(candidates)
            self._logger.info(
                "orchestrator.dry_run",
                tool=adapter.name,
                stage=adapter.stage.value,
                is_active=adapter.is_active,
                command=description,
            )
            return AdapterOutcome(
                tool=adapter.name,
                stage=adapter.stage,
                ok=True,
                dry_run=True,
                description=description,
            )

        allowed: list[Asset] = []
        denied = 0
        for asset in candidates:
            check = await ctx.scope_guard.check(
                asset.value, tool=adapter.name, is_active=adapter.is_active
            )
            if check.sendable:
                allowed.append(asset)
            else:
                denied += 1

        if not allowed:
            return AdapterOutcome(
                tool=adapter.name,
                stage=adapter.stage,
                ok=True,
                allowed_targets=0,
                denied_targets=denied,
            )

        last_error: str | None = None
        for attempt in range(1, self._max_retries + 2):
            result = None
            async with sem:
                try:
                    result = await asyncio.wait_for(
                        adapter.run(allowed, ctx), timeout=self._per_tool_timeout_s
                    )
                except TimeoutError:
                    last_error = f"timed out after {self._per_tool_timeout_s}s"
                except Exception as exc:  # noqa: BLE001 -- one adapter's bug can't kill the run
                    last_error = f"{type(exc).__name__}: {exc}"

            if result is not None and result.ok:
                parsed = adapter.parse(result.raw_output)
                discovered = await self._evidence_writer.write_many(
                    parsed, source_tool=adapter.name
                )
                return AdapterOutcome(
                    tool=adapter.name,
                    stage=adapter.stage,
                    ok=True,
                    evidence_count=len(parsed),
                    allowed_targets=len(allowed),
                    denied_targets=denied,
                    discovered_assets=discovered,
                )
            if result is not None and not result.ok:
                last_error = result.error or "adapter reported failure"

            if attempt <= self._max_retries:
                self._logger.warning(
                    "orchestrator.retry", tool=adapter.name, attempt=attempt, error=last_error
                )
                await asyncio.sleep(self._backoff_base_s * (2 ** (attempt - 1)))

        self._logger.error("orchestrator.adapter_failed", tool=adapter.name, error=last_error)
        return AdapterOutcome(
            tool=adapter.name,
            stage=adapter.stage,
            ok=False,
            error=last_error,
            allowed_targets=len(allowed),
            denied_targets=denied,
        )
