from __future__ import annotations

import dataclasses
import uuid

from kiyooo.config import (
    CategoryDefinition,
    ControlsFile,
    OrgContext,
    OwnershipOverridesFile,
    PredicateBlock,
    RouteConfig,
    ScopeConfig,
    TeamsFile,
    VendorMappingEntry,
    VendorMappingFile,
)
from kiyooo.db.models import AssetType
from kiyooo.ingest.base import ImportedFinding
from kiyooo.ingest.pipeline import ingest_batch, ingest_finding
from tests.detect.fakes import FakeFindingEvidenceRepository, FakeFindingRepository
from tests.graph.fakes import FakeAssetRepository
from tests.ingest.fakes import FakeEvidenceRepositoryForIngest, FakeExternalFindingRawRepository

_SLA = {"critical": 1, "high": 7, "medium": 30, "low": 90, "info": 180}


def _category(**overrides: object) -> CategoryDefinition:
    defaults: dict[str, object] = dict(
        id="exposed-database",
        name="Database exposed",
        version=1,
        severity_base="critical",
        applies_to=["tcp_service"],
        detect=PredicateBlock(any_of=[{"port_in": [3306]}]),
        triage_hints="test",
        route=RouteConfig(assign_to="appsec", sla_days=_SLA),
    )
    defaults.update(overrides)
    return CategoryDefinition.model_validate(defaults)


def _org_context(
    categories: list[CategoryDefinition], mappings: list[VendorMappingEntry]
) -> OrgContext:
    return OrgContext(
        scope=ScopeConfig(org_name="testcorp"),
        teams=TeamsFile(),
        controls=ControlsFile(),
        categories={c.id: c for c in categories},
        ownership_overrides=OwnershipOverridesFile(),
        vendor_mapping=VendorMappingFile(mappings=mappings),
    )


def _imported(external_id: str, vendor_issue_type: str = "sql-db-exposed") -> ImportedFinding:
    return ImportedFinding(
        external_id=external_id,
        vendor_issue_type=vendor_issue_type,
        title="MySQL exposed",
        vendor_severity="Medium",  # deliberately different from our category's "critical"
        asset_type=AssetType.TCP_SERVICE,
        asset_value="10.0.0.5:3306",
        evidence_content={"port": 3306},
        raw_payload={"raw": "payload"},
    )


def _repos() -> tuple[
    FakeAssetRepository,
    FakeEvidenceRepositoryForIngest,
    FakeFindingRepository,
    FakeFindingEvidenceRepository,
    FakeExternalFindingRawRepository,
]:
    return (
        FakeAssetRepository(),
        FakeEvidenceRepositoryForIngest(),
        FakeFindingRepository(),
        FakeFindingEvidenceRepository(),
        FakeExternalFindingRawRepository(),
    )


async def test_mapped_finding_creates_finding_row() -> None:
    org_context = _org_context(
        [_category()],
        [VendorMappingEntry(vendor_issue_type="sql-db-exposed", category_id="exposed-database")],
    )
    asset_repo, evidence_repo, finding_repo, finding_evidence_repo, external_repo = _repos()
    source_id = uuid.uuid4()

    status = await ingest_finding(
        _imported("vendor-1"),
        source_id=source_id,
        source_label="tenable",
        scan_run_id=uuid.uuid4(),
        org_context=org_context,
        asset_repo=asset_repo,
        evidence_repo=evidence_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
        external_finding_repo=external_repo,
    )

    assert status == "mapped"
    findings = await finding_repo.list_all()
    assert len(findings) == 1
    assert findings[0].category_id == "exposed-database"


async def test_ingested_evidence_redacts_secrets_before_storing() -> None:
    org_context = _org_context(
        [_category()],
        [VendorMappingEntry(vendor_issue_type="sql-db-exposed", category_id="exposed-database")],
    )
    asset_repo, evidence_repo, finding_repo, finding_evidence_repo, external_repo = _repos()
    imported = dataclasses.replace(
        _imported("vendor-1"), evidence_content={"raw": "Bearer ghp_" + "c" * 36}
    )

    await ingest_finding(
        imported,
        source_id=uuid.uuid4(),
        source_label="tenable",
        scan_run_id=uuid.uuid4(),
        org_context=org_context,
        asset_repo=asset_repo,
        evidence_repo=evidence_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
        external_finding_repo=external_repo,
    )

    assert len(evidence_repo.added) == 1
    stored = evidence_repo.added[0]
    assert stored.redacted is True
    assert "ghp_" not in str(stored.content_inline)


async def test_severity_never_inherited_from_vendor() -> None:
    org_context = _org_context(
        [_category(severity_base="critical")],
        [VendorMappingEntry(vendor_issue_type="sql-db-exposed", category_id="exposed-database")],
    )
    asset_repo, evidence_repo, finding_repo, finding_evidence_repo, external_repo = _repos()

    await ingest_finding(
        _imported("vendor-1"),  # vendor_severity="Medium"
        source_id=uuid.uuid4(),
        source_label="tenable",
        scan_run_id=uuid.uuid4(),
        org_context=org_context,
        asset_repo=asset_repo,
        evidence_repo=evidence_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
        external_finding_repo=external_repo,
    )

    findings = await finding_repo.list_all()
    assert findings[0].raw_severity.value == "critical"  # from category, not "Medium"


async def test_unmapped_vendor_issue_type() -> None:
    org_context = _org_context([_category()], [])  # no mapping entries at all
    asset_repo, evidence_repo, finding_repo, finding_evidence_repo, external_repo = _repos()

    status = await ingest_finding(
        _imported("vendor-1"),
        source_id=uuid.uuid4(),
        source_label="tenable",
        scan_run_id=uuid.uuid4(),
        org_context=org_context,
        asset_repo=asset_repo,
        evidence_repo=evidence_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
        external_finding_repo=external_repo,
    )

    assert status == "unmapped"
    assert await finding_repo.list_all() == []
    raw = external_repo.rows[next(iter(external_repo.rows))]
    assert "no vendor_mapping.yaml entry" in (raw.mapping_notes or "")


async def test_mapping_to_unknown_category_is_unmapped() -> None:
    org_context = _org_context(
        [], [VendorMappingEntry(vendor_issue_type="sql-db-exposed", category_id="does-not-exist")]
    )
    asset_repo, evidence_repo, finding_repo, finding_evidence_repo, external_repo = _repos()

    status = await ingest_finding(
        _imported("vendor-1"),
        source_id=uuid.uuid4(),
        source_label="tenable",
        scan_run_id=uuid.uuid4(),
        org_context=org_context,
        asset_repo=asset_repo,
        evidence_repo=evidence_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
        external_finding_repo=external_repo,
    )
    assert status == "unmapped"


async def test_category_not_applicable_to_asset_type_is_unmapped() -> None:
    org_context = _org_context(
        [_category(applies_to=["http_service"])],  # imported asset is tcp_service
        [VendorMappingEntry(vendor_issue_type="sql-db-exposed", category_id="exposed-database")],
    )
    asset_repo, evidence_repo, finding_repo, finding_evidence_repo, external_repo = _repos()

    status = await ingest_finding(
        _imported("vendor-1"),
        source_id=uuid.uuid4(),
        source_label="tenable",
        scan_run_id=uuid.uuid4(),
        org_context=org_context,
        asset_repo=asset_repo,
        evidence_repo=evidence_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
        external_finding_repo=external_repo,
    )
    assert status == "unmapped"


async def test_cross_tool_reconciliation_collapses_to_one_finding() -> None:
    """The DoD's own example: three products reporting the same issue on
    the same asset collapse into one Finding row, via the same fingerprint
    Stage 4's detect/engine.py computes.
    """
    org_context = _org_context(
        [_category()],
        [
            VendorMappingEntry(vendor_issue_type="sql-db-exposed", category_id="exposed-database"),
            VendorMappingEntry(vendor_issue_type="CVE-DB-1234", category_id="exposed-database"),
        ],
    )
    asset_repo, evidence_repo, finding_repo, finding_evidence_repo, external_repo = _repos()
    scan_run_id = uuid.uuid4()

    outcome = await ingest_batch(
        [
            _imported("qualys-1", "sql-db-exposed"),
            _imported("tenable-1", "CVE-DB-1234"),
        ],
        source_id=uuid.uuid4(),
        source_label="mixed",
        scan_run_id=scan_run_id,
        org_context=org_context,
        asset_repo=asset_repo,
        evidence_repo=evidence_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
        external_finding_repo=external_repo,
    )

    assert outcome.mapped == 2
    findings = await finding_repo.list_all()
    assert len(findings) == 1  # collapsed, not two separate findings


async def test_one_per_vendor_finding_category_does_not_collapse_distinct_issues() -> None:
    """The other half of the fingerprint discriminator: a category opted
    into `finding_granularity: one_per_vendor_finding` (Stage 14/15/16's
    "bucket" categories — many CVEs per image, many secrets per repo) must
    NOT collapse two genuinely distinct vendor findings on the same asset,
    unlike the default tested above. Caught live in Stage 15 testing before
    this field existed: two different secrets in one repo produced one
    Finding, not two.
    """
    org_context = _org_context(
        [_category(finding_granularity="one_per_vendor_finding")],
        [VendorMappingEntry(vendor_issue_type="sql-db-exposed", category_id="exposed-database")],
    )
    asset_repo, evidence_repo, finding_repo, finding_evidence_repo, external_repo = _repos()

    outcome = await ingest_batch(
        [_imported("cve-1"), _imported("cve-2")],
        source_id=uuid.uuid4(),
        source_label="trivy",
        scan_run_id=uuid.uuid4(),
        org_context=org_context,
        asset_repo=asset_repo,
        evidence_repo=evidence_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
        external_finding_repo=external_repo,
    )

    assert outcome.mapped == 2
    findings = await finding_repo.list_all()
    assert len(findings) == 2  # NOT collapsed — two distinct issues, two findings
