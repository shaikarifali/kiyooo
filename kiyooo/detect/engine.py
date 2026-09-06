"""YAML category evaluator. Evaluates every enabled
category against every asset it applies to, applies suppression — a
category's own `suppress_if` clauses and controls.yaml's compensating
controls — *before* a `Finding` row is ever created, computes the
fingerprint + cluster_id (`normalize/fingerprint.py`), and persists
`Finding`/`FindingEvidence` rows idempotently via `FindingRepository`/
`FindingEvidenceRepository`.

Severity is never adjusted here. A `reduce_severity` control is detected
and persisted as a `Control` row — visible to Stage 5's LLM bundle via
`controls_detected` — but `Finding.raw_severity` always stays the
category's own `severity_base`. `Verdict.adjusted_severity` /
`compensating_controls` (Stage 5) is where a control's effect on severity
actually gets recorded; the fingerprint-reconciliation rule in the design
is explicit that severity comes from the category, never from a detector.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from kiyooo.db.models import FindingDetector, FindingEvidenceRole, Severity
from kiyooo.detect.controls import detect_controls
from kiyooo.detect.evaluate import evaluate_block, evaluate_clauses_any
from kiyooo.detect.predicates import PredicateContext
from kiyooo.normalize.fingerprint import compute_cluster_id, compute_fingerprint

if TYPE_CHECKING:
    from uuid import UUID

    from kiyooo.config import CategoryDefinition, ControlsFile, OrgContext, SuppressionsFile
    from kiyooo.db.models import Asset, Control, Evidence
    from kiyooo.db.repo.control import ControlRepository
    from kiyooo.db.repo.evidence import EvidenceRepository
    from kiyooo.db.repo.finding import FindingRepository
    from kiyooo.db.repo.finding_evidence import FindingEvidenceRepository
    from kiyooo.enrich.epss import EpssScore
    from kiyooo.enrich.kev import KevCatalog


@dataclass(slots=True)
class DetectionOutcome:
    created_or_updated: int = 0
    suppressed: int = 0
    skipped_no_match: int = 0


def _suppressed_by_controls(
    category: CategoryDefinition,
    controls_file: ControlsFile,
    detected_controls: list[Control],
    severity: Severity,
) -> bool:
    detected_ids = {c.control_id for c in detected_controls}
    for control in controls_file.controls:
        if control.id not in detected_ids or control.action != "suppress":
            continue
        # No DB column records "a human confirmed this control once" yet —
        # see `detect/controls.py`'s docstring — so a control that requires
        # it is detected but never auto-suppresses.
        if control.requires_human_confirm_once:
            continue
        if severity in controls_file.never_suppress_severities:
            continue
        mitigates_this = "*" in control.mitigates or category.id in control.mitigates
        if not mitigates_this or category.id in control.never_applies_to:
            continue
        return True
    return False


def _suppressed_by_promoted_rule(
    category: CategoryDefinition, suppressions: SuppressionsFile, asset: Asset
) -> bool:
    """Stage 8: `feedback/promote.py` writes these entries after
    N humans agree the same category+asset is a false positive for the same
    reason — a literal match, not a predicate, since a free-text rationale
    can't be turned into a precise predicate without another model call
    (invariant #4).
    """
    return any(
        s.category_id == category.id and asset.value in s.asset_values
        for s in suppressions.suppressions
    )


async def _evaluate_asset(
    asset: Asset,
    evidence: list[Evidence],
    org_context: OrgContext,
    ctx_base: PredicateContext,
    scan_run_id: UUID,
    outcome: DetectionOutcome,
    control_repo: ControlRepository,
    finding_repo: FindingRepository,
    finding_evidence_repo: FindingEvidenceRepository,
) -> None:
    detected_controls = await detect_controls(
        org_context.controls.controls, asset, evidence, ctx_base, control_repo
    )
    ctx = PredicateContext(
        kev_catalog=ctx_base.kev_catalog,
        epss_scores=ctx_base.epss_scores,
        detected_controls=detected_controls,
        now=ctx_base.now,
    )

    for category in org_context.categories.values():
        if not category.enabled or asset.type.value not in category.applies_to:
            continue

        match = evaluate_block(category.detect, asset, evidence, ctx)
        if match is None:
            outcome.skipped_no_match += 1
            continue

        if category.suppress_if and evaluate_clauses_any(
            category.suppress_if, asset, evidence, ctx
        ):
            outcome.suppressed += 1
            continue

        severity = Severity(category.severity_base)
        if _suppressed_by_controls(category, org_context.controls, detected_controls, severity):
            outcome.suppressed += 1
            continue

        if _suppressed_by_promoted_rule(category, org_context.suppressions, asset):
            outcome.suppressed += 1
            continue

        discriminator = match.discriminator or ""
        fingerprint = compute_fingerprint(category.id, asset, discriminator)
        cluster_id = compute_cluster_id(category.id, discriminator)

        finding = await finding_repo.upsert(
            scan_run_id=scan_run_id,
            asset_id=asset.id,
            category_id=category.id,
            raw_severity=severity,
            title=category.name,
            description=f"{category.name} on {asset.value}",
            detector=FindingDetector.RULE,
            detector_ref=f"{category.id}@{category.version}",
            fingerprint=fingerprint,
            cluster_id=cluster_id,
            observed_at=ctx_base.now,
        )
        for evidence_id in match.evidence_ids:
            await finding_evidence_repo.link(finding.id, evidence_id, FindingEvidenceRole.PRIMARY)
        outcome.created_or_updated += 1


async def run_detection(
    org_context: OrgContext,
    assets: list[Asset],
    *,
    scan_run_id: UUID,
    evidence_repo: EvidenceRepository,
    control_repo: ControlRepository,
    finding_repo: FindingRepository,
    finding_evidence_repo: FindingEvidenceRepository,
    kev_catalog: KevCatalog | None = None,
    epss_scores: dict[str, EpssScore] | None = None,
) -> DetectionOutcome:
    all_evidence = await evidence_repo.for_scan_run(scan_run_id)
    evidence_by_asset: dict[UUID, list[Evidence]] = {}
    for item in all_evidence:
        evidence_by_asset.setdefault(item.asset_id, []).append(item)

    ctx_base = PredicateContext(
        kev_catalog=kev_catalog, epss_scores=epss_scores or {}, now=datetime.now(UTC)
    )
    outcome = DetectionOutcome()
    for asset in assets:
        await _evaluate_asset(
            asset,
            evidence_by_asset.get(asset.id, []),
            org_context,
            ctx_base,
            scan_run_id,
            outcome,
            control_repo,
            finding_repo,
            finding_evidence_repo,
        )
    return outcome
