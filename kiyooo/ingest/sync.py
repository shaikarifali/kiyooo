"""Runs one sync of a config-driven `CUSTOM` `ExternalFindingSource` —
shared by the CLI (`kiyooo ingest run --source <id>`) and the API
(`POST /api/ingest/sources/{id}/sync`) so the two can never drift, same
reasoning as `kiyooo.llm.credentials.resolve_credential` being shared.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx

from kiyooo.db.models import ScanRun, ScanRunStatus, ScanTrigger
from kiyooo.ingest.adapters.generic_rest import GenericRestConfig, fetch_items, parse_item
from kiyooo.ingest.adapters.mobile_static import MobileScanConfig, run_mobile_static_scan
from kiyooo.ingest.adapters.prowler import ProwlerConfig, parse_prowler_output, run_prowler
from kiyooo.ingest.adapters.trivy import TrivyConfig, parse_trivy_output, run_trivy
from kiyooo.ingest.adapters.trufflehog import (
    TrufflehogConfig,
    parse_trufflehog_output,
    run_trufflehog,
)
from kiyooo.ingest.pipeline import IngestOutcome, ingest_batch
from kiyooo.llm.credentials import resolve_credential

if TYPE_CHECKING:
    from kiyooo.config import OrgContext
    from kiyooo.db.models import ExternalFindingSource
    from kiyooo.db.repo.asset import AssetRepository
    from kiyooo.db.repo.evidence import EvidenceRepository
    from kiyooo.db.repo.external_finding import (
        ExternalFindingRawRepository,
        ExternalFindingSourceRepository,
    )
    from kiyooo.db.repo.finding import FindingRepository
    from kiyooo.db.repo.finding_evidence import FindingEvidenceRepository
    from kiyooo.db.repo.scan_run import ScanRunRepository


async def sync_generic_source(
    source: ExternalFindingSource,
    *,
    org_context: OrgContext,
    asset_repo: AssetRepository,
    evidence_repo: EvidenceRepository,
    finding_repo: FindingRepository,
    finding_evidence_repo: FindingEvidenceRepository,
    external_finding_repo: ExternalFindingRawRepository,
    source_repo: ExternalFindingSourceRepository,
    scan_run_repo: ScanRunRepository,
) -> IngestOutcome:
    config = GenericRestConfig.model_validate(source.config)
    credential = resolve_credential(config.credential_ref)
    since = source.last_sync_at.isoformat() if source.last_sync_at else None

    async with httpx.AsyncClient() as client:
        raw_items = await fetch_items(client, config, credential=credential, since=since)
    imported = [parse_item(item, config) for item in raw_items]

    now = datetime.now(UTC)
    scan_run_id = uuid.uuid4()
    await scan_run_repo.add(
        ScanRun(
            id=scan_run_id,
            started_at=now,
            finished_at=now,
            status=ScanRunStatus.COMPLETED,
            scope_hash="ingest",
            config_hash="ingest",
            trigger=ScanTrigger.INGEST,
        )
    )
    outcome = await ingest_batch(
        imported,
        source_id=source.id,
        source_label=source.name,
        scan_run_id=scan_run_id,
        org_context=org_context,
        asset_repo=asset_repo,
        evidence_repo=evidence_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
        external_finding_repo=external_finding_repo,
    )
    await source_repo.update_watermark(source.id, synced_at=now, cursor=since)
    return outcome


async def sync_prowler_source(
    source: ExternalFindingSource,
    *,
    org_context: OrgContext,
    asset_repo: AssetRepository,
    evidence_repo: EvidenceRepository,
    finding_repo: FindingRepository,
    finding_evidence_repo: FindingEvidenceRepository,
    external_finding_repo: ExternalFindingRawRepository,
    source_repo: ExternalFindingSourceRepository,
    scan_run_repo: ScanRunRepository,
) -> IngestOutcome:
    """Stage 13 — same shape as `sync_generic_source`, swapping
    an HTTP fetch for a Prowler subprocess run. Prowler always audits an
    account's current state (there is no `--since`), so there's no
    watermark to compute going in — `last_sync_at` still gets recorded on
    the way out, for the UI's "last synced" display.
    """
    config = ProwlerConfig.model_validate(source.config)
    raw = await run_prowler(config)
    imported = parse_prowler_output(raw)

    now = datetime.now(UTC)
    scan_run_id = uuid.uuid4()
    await scan_run_repo.add(
        ScanRun(
            id=scan_run_id,
            started_at=now,
            finished_at=now,
            status=ScanRunStatus.COMPLETED,
            scope_hash="ingest",
            config_hash="ingest",
            trigger=ScanTrigger.INGEST,
        )
    )
    outcome = await ingest_batch(
        imported,
        source_id=source.id,
        source_label=source.name,
        scan_run_id=scan_run_id,
        org_context=org_context,
        asset_repo=asset_repo,
        evidence_repo=evidence_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
        external_finding_repo=external_finding_repo,
    )
    await source_repo.update_watermark(source.id, synced_at=now, cursor=None)
    return outcome


async def sync_trufflehog_source(
    source: ExternalFindingSource,
    *,
    org_context: OrgContext,
    asset_repo: AssetRepository,
    evidence_repo: EvidenceRepository,
    finding_repo: FindingRepository,
    finding_evidence_repo: FindingEvidenceRepository,
    external_finding_repo: ExternalFindingRawRepository,
    source_repo: ExternalFindingSourceRepository,
    scan_run_repo: ScanRunRepository,
) -> IngestOutcome:
    """Stage 15 — same shape as `sync_prowler_source`/
    `sync_trivy_source`. A TruffleHog scan re-walks the repo's full history
    each run (no incremental `--since-commit` watermark wired up here);
    `(source_id, external_id)` idempotency in `ingest_batch` still means a
    re-run doesn't duplicate `Finding` rows for a secret already recorded.
    """
    config = TrufflehogConfig.model_validate(source.config)
    raw = await run_trufflehog(config)
    imported = parse_trufflehog_output(raw)

    now = datetime.now(UTC)
    scan_run_id = uuid.uuid4()
    await scan_run_repo.add(
        ScanRun(
            id=scan_run_id,
            started_at=now,
            finished_at=now,
            status=ScanRunStatus.COMPLETED,
            scope_hash="ingest",
            config_hash="ingest",
            trigger=ScanTrigger.INGEST,
        )
    )
    outcome = await ingest_batch(
        imported,
        source_id=source.id,
        source_label=source.name,
        scan_run_id=scan_run_id,
        org_context=org_context,
        asset_repo=asset_repo,
        evidence_repo=evidence_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
        external_finding_repo=external_finding_repo,
    )
    await source_repo.update_watermark(source.id, synced_at=now, cursor=None)
    return outcome


async def sync_mobile_static_source(
    source: ExternalFindingSource,
    *,
    org_context: OrgContext,
    asset_repo: AssetRepository,
    evidence_repo: EvidenceRepository,
    finding_repo: FindingRepository,
    finding_evidence_repo: FindingEvidenceRepository,
    external_finding_repo: ExternalFindingRawRepository,
    source_repo: ExternalFindingSourceRepository,
    scan_run_repo: ScanRunRepository,
) -> IngestOutcome:
    """Stage 16 — same shape as the other `sync_*_source`
    functions, except the adapter itself (`run_mobile_static_scan`) already
    returns `ImportedFinding`s directly rather than a raw-bytes/parse pair
    (there's no single tool's stdout to hand back — see that module's
    docstring).
    """
    config = MobileScanConfig.model_validate(source.config)
    imported = await run_mobile_static_scan(config)

    now = datetime.now(UTC)
    scan_run_id = uuid.uuid4()
    await scan_run_repo.add(
        ScanRun(
            id=scan_run_id,
            started_at=now,
            finished_at=now,
            status=ScanRunStatus.COMPLETED,
            scope_hash="ingest",
            config_hash="ingest",
            trigger=ScanTrigger.INGEST,
        )
    )
    outcome = await ingest_batch(
        imported,
        source_id=source.id,
        source_label=source.name,
        scan_run_id=scan_run_id,
        org_context=org_context,
        asset_repo=asset_repo,
        evidence_repo=evidence_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
        external_finding_repo=external_finding_repo,
    )
    await source_repo.update_watermark(source.id, synced_at=now, cursor=None)
    return outcome


async def sync_trivy_source(
    source: ExternalFindingSource,
    *,
    org_context: OrgContext,
    asset_repo: AssetRepository,
    evidence_repo: EvidenceRepository,
    finding_repo: FindingRepository,
    finding_evidence_repo: FindingEvidenceRepository,
    external_finding_repo: ExternalFindingRawRepository,
    source_repo: ExternalFindingSourceRepository,
    scan_run_repo: ScanRunRepository,
) -> IngestOutcome:
    """Stage 14 — same shape as `sync_prowler_source`, swapping
    the subprocess call for Trivy's. Like Prowler, a Trivy scan always
    reflects current state; there's no `--since` watermark to compute.
    """
    config = TrivyConfig.model_validate(source.config)
    raw = await run_trivy(config)
    imported = parse_trivy_output(raw)

    now = datetime.now(UTC)
    scan_run_id = uuid.uuid4()
    await scan_run_repo.add(
        ScanRun(
            id=scan_run_id,
            started_at=now,
            finished_at=now,
            status=ScanRunStatus.COMPLETED,
            scope_hash="ingest",
            config_hash="ingest",
            trigger=ScanTrigger.INGEST,
        )
    )
    outcome = await ingest_batch(
        imported,
        source_id=source.id,
        source_label=source.name,
        scan_run_id=scan_run_id,
        org_context=org_context,
        asset_repo=asset_repo,
        evidence_repo=evidence_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
        external_finding_repo=external_finding_repo,
    )
    await source_repo.update_watermark(source.id, synced_at=now, cursor=None)
    return outcome
