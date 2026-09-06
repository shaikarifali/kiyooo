from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kiyooo.config import (
    CategoryDefinition,
    ControlDefinition,
    ControlsFile,
    OrgContext,
    OwnershipOverridesFile,
    PredicateBlock,
    RouteConfig,
    ScopeConfig,
    SuppressionEntry,
    SuppressionsFile,
    TeamsFile,
)
from kiyooo.db.models import AssetType, Evidence, EvidenceKind
from kiyooo.detect.engine import run_detection
from tests.detect.fakes import (
    FakeControlRepository,
    FakeEvidenceRepository,
    FakeFindingEvidenceRepository,
    FakeFindingRepository,
)
from tests.enrich.factories import make_asset

_SLA = {"critical": 1, "high": 7, "medium": 30, "low": 90, "info": 180}


def _route() -> RouteConfig:
    return RouteConfig(assign_to="appsec", cc=[], notify_channels=[], sla_days=_SLA)


def _database_category(
    *,
    severity_base: str = "critical",
    suppress_if: list[dict[str, object]] | None = None,
) -> CategoryDefinition:
    return CategoryDefinition(
        id="exposed-database",
        name="Database reachable from the internet",
        version=1,
        enabled=True,
        severity_base=severity_base,  # type: ignore[arg-type]
        applies_to=["tcp_service"],
        detect=PredicateBlock(any_of=[{"port_in": [3306, 5432]}]),
        suppress_if=suppress_if or [],
        triage_hints="test",
        route=_route(),
    )


def _org_context(
    categories: list[CategoryDefinition],
    controls: list[ControlDefinition] | None = None,
    suppressions: list[SuppressionEntry] | None = None,
) -> OrgContext:
    return OrgContext(
        scope=ScopeConfig(org_name="testcorp"),
        teams=TeamsFile(),
        controls=ControlsFile(controls=controls or []),
        categories={c.id: c for c in categories},
        ownership_overrides=OwnershipOverridesFile(),
        suppressions=SuppressionsFile(suppressions=suppressions or []),
    )


def _port_evidence(scan_run_id: uuid.UUID, asset_id: uuid.UUID, port: int) -> Evidence:
    return Evidence(
        id=f"ev_{uuid.uuid4().hex[:8]}",
        scan_run_id=scan_run_id,
        asset_id=asset_id,
        kind=EvidenceKind.PORT_BANNER,
        source_tool="fixture",
        collected_at=datetime.now(UTC),
        content_ref=None,
        content_inline={"port": port},
        content_hash="fixture",
        size_bytes=None,
        redacted=False,
    )


def _repos() -> tuple[FakeControlRepository, FakeFindingRepository, FakeFindingEvidenceRepository]:
    return FakeControlRepository(), FakeFindingRepository(), FakeFindingEvidenceRepository()


async def test_run_detection_creates_finding_for_matching_asset() -> None:
    scan_run_id = uuid.uuid4()
    asset = make_asset(AssetType.TCP_SERVICE, "10.0.0.5:3306")
    evidence_repo = FakeEvidenceRepository([_port_evidence(scan_run_id, asset.id, 3306)])
    control_repo, finding_repo, finding_evidence_repo = _repos()
    org_context = _org_context([_database_category()])

    outcome = await run_detection(
        org_context,
        [asset],
        scan_run_id=scan_run_id,
        evidence_repo=evidence_repo,
        control_repo=control_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
    )

    assert outcome.created_or_updated == 1
    assert outcome.suppressed == 0
    findings = await finding_repo.list_all()
    assert len(findings) == 1
    assert findings[0].category_id == "exposed-database"
    assert findings[0].asset_id == asset.id


async def test_run_detection_no_match_creates_nothing() -> None:
    scan_run_id = uuid.uuid4()
    asset = make_asset(AssetType.TCP_SERVICE, "10.0.0.5:22")
    evidence_repo = FakeEvidenceRepository([_port_evidence(scan_run_id, asset.id, 22)])
    control_repo, finding_repo, finding_evidence_repo = _repos()
    org_context = _org_context([_database_category()])

    outcome = await run_detection(
        org_context,
        [asset],
        scan_run_id=scan_run_id,
        evidence_repo=evidence_repo,
        control_repo=control_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
    )

    assert outcome.created_or_updated == 0
    assert outcome.skipped_no_match == 1
    assert await finding_repo.list_all() == []


async def test_run_detection_suppressed_by_promoted_suppressions_yaml_entry() -> None:
    """Stage 8: `feedback/promote.py` writes a suppressions.yaml
    entry after N humans agree a category+asset combo is FP for the same
    reason — this proves that entry actually stops the finding from firing
    again, not just sitting inert in org-context.
    """
    scan_run_id = uuid.uuid4()
    asset = make_asset(AssetType.TCP_SERVICE, "10.0.0.5:3306")
    evidence_repo = FakeEvidenceRepository([_port_evidence(scan_run_id, asset.id, 3306)])
    control_repo, finding_repo, finding_evidence_repo = _repos()
    org_context = _org_context(
        [_database_category()],
        suppressions=[
            SuppressionEntry(
                id="promoted-exposed-database-abc123",
                category_id="exposed-database",
                asset_values=[asset.value],
                reason="confirmed internal-only via VPN, humans agreed FP 5x",
                promoted_from_review_ids=["r1", "r2", "r3", "r4", "r5"],
            )
        ],
    )

    outcome = await run_detection(
        org_context,
        [asset],
        scan_run_id=scan_run_id,
        evidence_repo=evidence_repo,
        control_repo=control_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
    )

    assert outcome.created_or_updated == 0
    assert outcome.suppressed == 1
    assert await finding_repo.list_all() == []


async def test_run_detection_suppressed_by_category_suppress_if() -> None:
    scan_run_id = uuid.uuid4()
    asset = make_asset(AssetType.TCP_SERVICE, "10.0.0.5:3306")
    evidence_repo = FakeEvidenceRepository(
        [
            _port_evidence(scan_run_id, asset.id, 3306),
            Evidence(
                id="ev_cert",
                scan_run_id=scan_run_id,
                asset_id=asset.id,
                kind=EvidenceKind.TLS_CERT,
                source_tool="fixture",
                collected_at=datetime.now(UTC),
                content_ref=None,
                content_inline={"requires_client_cert": True},
                content_hash="fixture",
                size_bytes=None,
                redacted=False,
            ),
        ]
    )
    control_repo, finding_repo, finding_evidence_repo = _repos()

    mtls_control = ControlDefinition(
        id="mtls_required",
        detect=PredicateBlock(all_of=[{"tls_handshake_requires_client_cert": True}]),
        mitigates=["*"],
        action="suppress",
    )
    category = _database_category(suppress_if=[{"has_control": "mtls_required"}])
    org_context = _org_context([category], [mtls_control])

    outcome = await run_detection(
        org_context,
        [asset],
        scan_run_id=scan_run_id,
        evidence_repo=evidence_repo,
        control_repo=control_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
    )

    assert outcome.created_or_updated == 0
    assert outcome.suppressed == 1
    assert await finding_repo.list_all() == []


async def test_run_detection_suppressed_by_controls_yaml_action() -> None:
    scan_run_id = uuid.uuid4()
    asset = make_asset(AssetType.TCP_SERVICE, "10.0.0.5:3306")
    evidence_repo = FakeEvidenceRepository(
        [
            _port_evidence(scan_run_id, asset.id, 3306),
            Evidence(
                id="ev_hdr",
                scan_run_id=scan_run_id,
                asset_id=asset.id,
                kind=EvidenceKind.HTTP_RESPONSE,
                source_tool="fixture",
                collected_at=datetime.now(UTC),
                content_ref=None,
                content_inline={"header": {"x-auth-request-user": "alice"}},
                content_hash="fixture",
                size_bytes=None,
                redacted=False,
            ),
        ]
    )
    control_repo, finding_repo, finding_evidence_repo = _repos()

    sso_control = ControlDefinition(
        id="sso_gateway",
        detect=PredicateBlock(any_of=[{"http_header_matches": {"x-auth-request-user": ".+"}}]),
        mitigates=["exposed-database"],
        action="suppress",
        requires_human_confirm_once=False,
    )
    # never_suppress_severities defaults to ["critical"] — use a lower
    # severity here so this test actually exercises the suppress path; the
    # critical guard rail gets its own dedicated test below.
    category = _database_category(severity_base="high")
    org_context = _org_context([category], [sso_control])

    outcome = await run_detection(
        org_context,
        [asset],
        scan_run_id=scan_run_id,
        evidence_repo=evidence_repo,
        control_repo=control_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
    )

    assert outcome.suppressed == 1
    assert await finding_repo.list_all() == []


async def test_run_detection_requires_human_confirm_once_never_auto_suppresses() -> None:
    scan_run_id = uuid.uuid4()
    asset = make_asset(AssetType.TCP_SERVICE, "10.0.0.5:3306")
    evidence_repo = FakeEvidenceRepository(
        [
            _port_evidence(scan_run_id, asset.id, 3306),
            Evidence(
                id="ev_hdr",
                scan_run_id=scan_run_id,
                asset_id=asset.id,
                kind=EvidenceKind.HTTP_RESPONSE,
                source_tool="fixture",
                collected_at=datetime.now(UTC),
                content_ref=None,
                content_inline={"header": {"x-auth-request-user": "alice"}},
                content_hash="fixture",
                size_bytes=None,
                redacted=False,
            ),
        ]
    )
    control_repo, finding_repo, finding_evidence_repo = _repos()

    sso_control = ControlDefinition(
        id="sso_gateway",
        detect=PredicateBlock(any_of=[{"http_header_matches": {"x-auth-request-user": ".+"}}]),
        mitigates=["exposed-database"],
        action="suppress",
        requires_human_confirm_once=True,
    )
    category = _database_category()
    org_context = _org_context([category], [sso_control])

    outcome = await run_detection(
        org_context,
        [asset],
        scan_run_id=scan_run_id,
        evidence_repo=evidence_repo,
        control_repo=control_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
    )

    # requires_human_confirm_once controls are detected (visible to Stage 5)
    # but never auto-suppress — the finding still gets created.
    assert outcome.created_or_updated == 1
    assert outcome.suppressed == 0
    rows = await control_repo.list_for_asset(asset.id)
    assert any(c.control_id == "sso_gateway" for c in rows)


async def test_run_detection_never_suppress_severities_blocks_suppression() -> None:
    scan_run_id = uuid.uuid4()
    asset = make_asset(AssetType.TCP_SERVICE, "10.0.0.5:3306")
    evidence_repo = FakeEvidenceRepository(
        [
            _port_evidence(scan_run_id, asset.id, 3306),
            Evidence(
                id="ev_hdr",
                scan_run_id=scan_run_id,
                asset_id=asset.id,
                kind=EvidenceKind.HTTP_RESPONSE,
                source_tool="fixture",
                collected_at=datetime.now(UTC),
                content_ref=None,
                content_inline={"header": {"x-auth-request-user": "alice"}},
                content_hash="fixture",
                size_bytes=None,
                redacted=False,
            ),
        ]
    )
    control_repo, finding_repo, finding_evidence_repo = _repos()

    sso_control = ControlDefinition(
        id="sso_gateway",
        detect=PredicateBlock(any_of=[{"http_header_matches": {"x-auth-request-user": ".+"}}]),
        mitigates=["exposed-database"],
        action="suppress",
        requires_human_confirm_once=False,
    )
    category = _database_category()  # severity_base=critical
    org_context = OrgContext(
        scope=ScopeConfig(org_name="testcorp"),
        teams=TeamsFile(),
        controls=ControlsFile(controls=[sso_control], never_suppress_severities=["critical"]),
        categories={category.id: category},
        ownership_overrides=OwnershipOverridesFile(),
    )

    outcome = await run_detection(
        org_context,
        [asset],
        scan_run_id=scan_run_id,
        evidence_repo=evidence_repo,
        control_repo=control_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
    )

    assert outcome.created_or_updated == 1
    assert outcome.suppressed == 0


async def test_run_detection_rerun_same_scan_is_idempotent() -> None:
    scan_run_id = uuid.uuid4()
    asset = make_asset(AssetType.TCP_SERVICE, "10.0.0.5:3306")
    evidence_repo = FakeEvidenceRepository([_port_evidence(scan_run_id, asset.id, 3306)])
    control_repo, finding_repo, finding_evidence_repo = _repos()
    org_context = _org_context([_database_category()])

    kwargs = dict(
        org_context=org_context,
        assets=[asset],
        scan_run_id=scan_run_id,
        evidence_repo=evidence_repo,
        control_repo=control_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
    )
    await run_detection(**kwargs)  # type: ignore[arg-type]
    await run_detection(**kwargs)  # type: ignore[arg-type]

    findings = await finding_repo.list_all()
    assert len(findings) == 1


async def test_run_detection_clusters_same_category_and_discriminator_across_assets() -> None:
    scan_run_id = uuid.uuid4()
    assets = [make_asset(AssetType.TCP_SERVICE, f"10.0.0.{i}:3306") for i in range(1, 41)]
    evidence = [_port_evidence(scan_run_id, a.id, 3306) for a in assets]
    evidence_repo = FakeEvidenceRepository(evidence)
    control_repo, finding_repo, finding_evidence_repo = _repos()
    org_context = _org_context([_database_category()])

    outcome = await run_detection(
        org_context,
        assets,
        scan_run_id=scan_run_id,
        evidence_repo=evidence_repo,
        control_repo=control_repo,
        finding_repo=finding_repo,
        finding_evidence_repo=finding_evidence_repo,
    )

    assert outcome.created_or_updated == 40
    findings = await finding_repo.list_all()
    cluster_ids = {f.cluster_id for f in findings}
    assert len(cluster_ids) == 1
