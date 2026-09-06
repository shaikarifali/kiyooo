"""Orchestrates one import batch: map each vendor
finding onto our asset/evidence/finding schema, reusing Stage 4's exact
fingerprint + upsert path so cross-tool reconciliation is automatic — the
same category + same asset identity always yields the same fingerprint no
matter which detector (our own rule engine, or an imported vendor finding)
produced it. "We ingest their findings; we do not inherit their
severity" — `Finding.raw_severity` always comes from `category.
severity_base`, never `imported.vendor_severity`.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from kiyooo.db.models import Evidence, EvidenceKind, FindingDetector, FindingEvidenceRole, Severity
from kiyooo.graph.builder import upsert_asset
from kiyooo.ingest.mapper import map_category
from kiyooo.normalize.fingerprint import compute_cluster_id, compute_fingerprint
from kiyooo.normalize.injection import scan_evidence_content
from kiyooo.normalize.redact import redact_content

if TYPE_CHECKING:
    from uuid import UUID

    from kiyooo.config import OrgContext
    from kiyooo.db.repo.asset import AssetRepository
    from kiyooo.db.repo.evidence import EvidenceRepository
    from kiyooo.db.repo.external_finding import ExternalFindingRawRepository
    from kiyooo.db.repo.finding import FindingRepository
    from kiyooo.db.repo.finding_evidence import FindingEvidenceRepository
    from kiyooo.ingest.base import ImportedFinding


@dataclass(slots=True)
class IngestOutcome:
    mapped: int = 0
    unmapped: int = 0


async def ingest_finding(
    imported: ImportedFinding,
    *,
    source_id: UUID,
    source_label: str,
    scan_run_id: UUID,
    org_context: OrgContext,
    asset_repo: AssetRepository,
    evidence_repo: EvidenceRepository,
    finding_repo: FindingRepository,
    finding_evidence_repo: FindingEvidenceRepository,
    external_finding_repo: ExternalFindingRawRepository,
) -> str:
    """Returns the persisted mapping_status: "mapped" or "unmapped"."""
    now = datetime.now(UTC)
    asset = await upsert_asset(
        asset_repo, imported.asset_type, imported.asset_value, confidence_in_scope=1.0
    )

    # Invariant #7: redact before hashing/storing — a vendor export can
    # carry a live credential in a raw response field just as easily as
    # our own recon adapters can.
    redacted_content, secrets_found = redact_content(imported.evidence_content)
    if secrets_found:
        redacted_content = {
            **redacted_content,
            "_redacted_secrets": [
                {"secret_type": s.secret_type, "partial_hash": s.partial_hash}
                for s in secrets_found
            ],
        }

    content_json = json.dumps(redacted_content, sort_keys=True, default=str)
    evidence = await evidence_repo.add(
        Evidence(
            id=f"ev_ingest_{uuid.uuid4().hex[:12]}",
            scan_run_id=scan_run_id,
            asset_id=asset.id,
            kind=EvidenceKind.EXTERNAL_FINDING,
            source_tool=f"ingest:{source_label}",
            collected_at=now,
            content_ref=None,
            content_inline=redacted_content,
            content_hash=hashlib.sha256(content_json.encode()).hexdigest(),
            size_bytes=len(content_json),
            redacted=bool(secrets_found),
            injection_suspected=scan_evidence_content(redacted_content),
        )
    )

    category_id = map_category(imported.vendor_issue_type, org_context.vendor_mapping)
    category = org_context.categories.get(category_id) if category_id else None

    mapped_finding_id: UUID | None = None
    mapping_status = "unmapped"
    mapping_notes: str | None = None

    if category_id is None:
        mapping_notes = f"no vendor_mapping.yaml entry for {imported.vendor_issue_type!r}"
    elif category is None:
        mapping_notes = f"vendor_mapping.yaml points at unknown category {category_id!r}"
    elif not category.enabled:
        mapping_notes = f"category {category_id!r} is disabled"
    elif asset.type.value not in category.applies_to:
        mapping_notes = (
            f"category {category_id!r} does not apply to asset type {asset.type.value!r}"
        )
    else:
        # `finding_granularity` (config.py) decides the discriminator:
        # "one_per_asset" (default) is what makes cross-tool reconciliation
        # work — three vendors reporting the same category on the same
        # asset collapse to one Finding regardless of their different
        # external_ids (Stage 1b's DoD, tested by
        # test_cross_tool_reconciliation_collapses_to_one_finding).
        # "one_per_vendor_finding" is for bucket categories
        # (`vulnerable-base-image`, `leaked-secret-in-repo`, ...) where many
        # genuinely distinct issues deliberately share one category+asset —
        # caught live in Stage 15 testing, two different secrets in one
        # repo produced one Finding before this field existed.
        discriminator = (
            imported.external_id if category.finding_granularity == "one_per_vendor_finding" else ""
        )
        fingerprint = compute_fingerprint(category.id, asset, discriminator)
        cluster_id = compute_cluster_id(category.id, discriminator)
        finding = await finding_repo.upsert(
            scan_run_id=scan_run_id,
            asset_id=asset.id,
            category_id=category.id,
            raw_severity=Severity(category.severity_base),
            title=category.name,
            description=imported.title,
            detector=FindingDetector.EXTERNAL,
            detector_ref=f"{source_label}:{imported.external_id}",
            fingerprint=fingerprint,
            cluster_id=cluster_id,
            observed_at=now,
        )
        await finding_evidence_repo.link(finding.id, evidence.id, FindingEvidenceRole.SUPPORTING)
        mapped_finding_id = finding.id
        mapping_status = "mapped"

    await external_finding_repo.upsert(
        source_id,
        imported.external_id,
        payload=imported.raw_payload,
        ingested_at=now,
        mapped_finding_id=mapped_finding_id,
        mapping_status=mapping_status,
        mapping_notes=mapping_notes,
    )
    return mapping_status


async def ingest_batch(
    findings: list[ImportedFinding],
    *,
    source_id: UUID,
    source_label: str,
    scan_run_id: UUID,
    org_context: OrgContext,
    asset_repo: AssetRepository,
    evidence_repo: EvidenceRepository,
    finding_repo: FindingRepository,
    finding_evidence_repo: FindingEvidenceRepository,
    external_finding_repo: ExternalFindingRawRepository,
) -> IngestOutcome:
    outcome = IngestOutcome()
    for imported in findings:
        status = await ingest_finding(
            imported,
            source_id=source_id,
            source_label=source_label,
            scan_run_id=scan_run_id,
            org_context=org_context,
            asset_repo=asset_repo,
            evidence_repo=evidence_repo,
            finding_repo=finding_repo,
            finding_evidence_repo=finding_evidence_repo,
            external_finding_repo=external_finding_repo,
        )
        if status == "mapped":
            outcome.mapped += 1
        else:
            outcome.unmapped += 1
    return outcome
