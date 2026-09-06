from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from kiyooo.config import (
    CategoryDefinition,
    ControlsFile,
    OrgContext,
    OwnershipOverridesFile,
    PredicateBlock,
    RouteConfig,
    ScopeConfig,
    TeamDefinition,
    TeamsFile,
)
from kiyooo.db.models import (
    Asset,
    AssetType,
    Finding,
    FindingDetector,
    FindingStatus,
    OwnershipSource,
    OwnerType,
    Severity,
    TicketSystem,
    Verdict,
    VerdictPassType,
    VerdictValue,
)
from kiyooo.route.pipeline import route_findings
from kiyooo.route.sinks.base import SinkResult
from tests.enrich.fakes import FakeOwnershipRepository
from tests.graph.fakes import FakeAssetRepository
from tests.route.fakes import (
    FakeApprovalRepository,
    FakeFindingRepositoryForRoute,
    FakeTicketRepository,
    FakeVerdictRepository,
)

_NOW = datetime.now(UTC)
_SLA = {"critical": 1, "high": 7, "medium": 30, "low": 90, "info": 180}
_ORG_CONTEXT_PATH = Path("org-context.example")


class FakeSink:
    system = TicketSystem.WEBHOOK

    def __init__(self) -> None:
        self.created: list[dict[str, object]] = []
        self.reopened: list[str] = []

    async def create(
        self,
        client: object,
        *,
        subject: str,
        body: str,
        assignee: str | None,
        cc: list[str],
        sla_due_at: object,
    ) -> SinkResult:
        self.created.append({"subject": subject, "assignee": assignee, "cc": cc})
        return SinkResult(external_key=f"ext-{len(self.created)}", status="open")

    async def reopen(self, client: object, *, external_key: str, body: str) -> SinkResult:
        self.reopened.append(external_key)
        return SinkResult(external_key=external_key, status="open")


def _category(
    *, autonomy_level: int, assign_to: str = "appsec", cc: list[str] | None = None
) -> CategoryDefinition:
    return CategoryDefinition.model_validate(
        dict(
            id="exposed-database",
            name="Database exposed",
            version=1,
            severity_base="critical",
            applies_to=["tcp_service"],
            detect=PredicateBlock(any_of=[{"port_in": [3306]}]),
            triage_hints="test",
            route=RouteConfig(
                assign_to=assign_to,
                cc=cc or [],
                sla_days=_SLA,
                autonomy_level=autonomy_level,  # type: ignore[arg-type]
            ),
        )
    )


def _org_context(
    category: CategoryDefinition, teams: list[TeamDefinition] | None = None
) -> OrgContext:
    return OrgContext(
        scope=ScopeConfig(org_name="testcorp"),
        teams=TeamsFile(teams=teams or []),
        controls=ControlsFile(),
        categories={category.id: category},
        ownership_overrides=OwnershipOverridesFile(),
    )


def _asset(value: str = "10.0.0.5:3306") -> Asset:
    return Asset(
        id=uuid.uuid4(),
        type=AssetType.TCP_SERVICE,
        value=value,
        first_seen=_NOW,
        last_seen=_NOW,
        confidence_in_scope=1.0,
        attributes={},
    )


def _finding(
    asset: Asset, category: CategoryDefinition, *, cluster_id: uuid.UUID | None = None
) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        scan_run_id=uuid.uuid4(),
        asset_id=asset.id,
        category_id=category.id,
        raw_severity=Severity.CRITICAL,
        title=category.name,
        detector=FindingDetector.RULE,
        fingerprint=f"fp-{uuid.uuid4()}",
        cluster_id=cluster_id,
        first_seen=_NOW,
        last_seen=_NOW,
        status=FindingStatus.TRIAGED,
    )


def _verdict(
    finding_id: uuid.UUID, *, verdict: VerdictValue = VerdictValue.TRUE_POSITIVE
) -> Verdict:
    return Verdict(
        id=uuid.uuid4(),
        finding_id=finding_id,
        model="test-model",
        model_version="test-model",
        prompt_version="v1",
        pass_type=VerdictPassType.BULK,
        verdict=verdict,
        confidence=0.9,
        adjusted_severity=Severity.HIGH,
        reasoning="clearly exposed",
        business_impact_hypothesis="customer data at risk",
        citations=["ev_1"],
        compensating_controls=[],
        exploitability={"internet_reachable": True, "authentication_required": False},
        remediation={
            "summary": "close the port",
            "steps": ["firewall it"],
            "verification": "rescan",
        },
        input_hash="hash",
        tokens_in=1,
        tokens_out=1,
        cost_usd=0.0,
        latency_ms=1,
        created_at=_NOW,
    )


def _repos(
    findings: list[Finding],
) -> tuple[
    FakeAssetRepository,
    FakeOwnershipRepository,
    FakeVerdictRepository,
    FakeFindingRepositoryForRoute,
    FakeTicketRepository,
    FakeApprovalRepository,
]:
    return (
        FakeAssetRepository(),
        FakeOwnershipRepository(),
        FakeVerdictRepository(),
        FakeFindingRepositoryForRoute(findings),
        FakeTicketRepository(),
        FakeApprovalRepository(),
    )


async def test_shadow_autonomy_sends_nothing() -> None:
    category = _category(autonomy_level=0)
    org_context = _org_context(category)
    asset = _asset()
    finding = _finding(asset, category)
    asset_repo, ownership_repo, verdict_repo, finding_repo, ticket_repo, approval_repo = _repos(
        [finding]
    )
    asset_repo._by_id[asset.id] = asset
    verdict_repo.seed(finding.id, _verdict(finding.id))

    outcome = await route_findings(
        org_context,
        [finding],
        sinks={},
        http_client=object(),  # type: ignore[arg-type]
        org_context_path=_ORG_CONTEXT_PATH,
        asset_repo=asset_repo,
        ownership_repo=ownership_repo,
        verdict_repo=verdict_repo,
        finding_repo=finding_repo,
        ticket_repo=ticket_repo,
        approval_repo=approval_repo,
        now=_NOW,
    )

    assert outcome.shadowed == 1
    assert outcome.drafted == 0
    assert outcome.filed == 0
    assert approval_repo._by_id == {}
    assert ticket_repo._by_id == {}
    assert finding.status == FindingStatus.TRIAGED  # unchanged


async def test_draft_autonomy_creates_approval_with_resolved_targets() -> None:
    teams = [
        TeamDefinition(
            id="appsec", manager="appsec-manager@example.com", members=["dev@example.com"]
        )
    ]
    category = _category(autonomy_level=1, assign_to="owner_of_asset", cc=["manager_of_owner"])
    org_context = _org_context(category, teams)
    asset = _asset()
    finding = _finding(asset, category)
    asset_repo, ownership_repo, verdict_repo, finding_repo, ticket_repo, approval_repo = _repos(
        [finding]
    )
    asset_repo._by_id[asset.id] = asset
    ownership_repo.seed(
        asset.id,
        source=OwnershipSource.CODEOWNERS,
        owner_type=OwnerType.USER,
        owner_ref="dev@example.com",
        confidence=0.9,
    )
    verdict_repo.seed(finding.id, _verdict(finding.id))

    outcome = await route_findings(
        org_context,
        [finding],
        sinks={},
        http_client=object(),  # type: ignore[arg-type]
        org_context_path=_ORG_CONTEXT_PATH,
        asset_repo=asset_repo,
        ownership_repo=ownership_repo,
        verdict_repo=verdict_repo,
        finding_repo=finding_repo,
        ticket_repo=ticket_repo,
        approval_repo=approval_repo,
        now=_NOW,
    )

    assert outcome.drafted == 1
    approvals = list(approval_repo._by_id.values())
    assert len(approvals) == 1
    assert approvals[0].target_assignee == "dev@example.com"
    assert approvals[0].target_cc == ["appsec-manager@example.com"]
    assert finding.status == FindingStatus.TRIAGED  # nothing sent yet


async def test_auto_file_creates_ticket_and_marks_routed() -> None:
    category = _category(autonomy_level=3)
    org_context = _org_context(category)
    asset = _asset()
    finding = _finding(asset, category)
    asset_repo, ownership_repo, verdict_repo, finding_repo, ticket_repo, approval_repo = _repos(
        [finding]
    )
    asset_repo._by_id[asset.id] = asset
    verdict_repo.seed(finding.id, _verdict(finding.id))
    sink = FakeSink()

    outcome = await route_findings(
        org_context,
        [finding],
        sinks={TicketSystem.WEBHOOK: sink},
        http_client=object(),  # type: ignore[arg-type]
        org_context_path=_ORG_CONTEXT_PATH,
        asset_repo=asset_repo,
        ownership_repo=ownership_repo,
        verdict_repo=verdict_repo,
        finding_repo=finding_repo,
        ticket_repo=ticket_repo,
        approval_repo=approval_repo,
        now=_NOW,
    )

    assert outcome.filed == 1
    assert len(sink.created) == 1
    assert finding.status == FindingStatus.ROUTED
    ticket = await ticket_repo.get_by_finding(finding.id)
    assert ticket is not None
    assert ticket.external_key == "ext-1"


async def test_cluster_batching_files_one_ticket_for_the_whole_cluster() -> None:
    category = _category(autonomy_level=3)
    org_context = _org_context(category)
    cluster_id = uuid.uuid4()
    asset_a = _asset("10.0.0.5:3306")
    asset_b = _asset("10.0.0.6:3306")
    finding_a = _finding(asset_a, category, cluster_id=cluster_id)
    finding_b = _finding(asset_b, category, cluster_id=cluster_id)
    finding_b.first_seen = _NOW  # same first_seen tie is fine; order doesn't matter here

    asset_repo, ownership_repo, verdict_repo, finding_repo, ticket_repo, approval_repo = _repos(
        [finding_a, finding_b]
    )
    asset_repo._by_id[asset_a.id] = asset_a
    asset_repo._by_id[asset_b.id] = asset_b
    verdict_repo.seed(finding_a.id, _verdict(finding_a.id))
    verdict_repo.seed(finding_b.id, _verdict(finding_b.id))
    sink = FakeSink()

    outcome = await route_findings(
        org_context,
        [finding_a, finding_b],
        sinks={TicketSystem.WEBHOOK: sink},
        http_client=object(),  # type: ignore[arg-type]
        org_context_path=_ORG_CONTEXT_PATH,
        asset_repo=asset_repo,
        ownership_repo=ownership_repo,
        verdict_repo=verdict_repo,
        finding_repo=finding_repo,
        ticket_repo=ticket_repo,
        approval_repo=approval_repo,
        now=_NOW,
    )

    assert outcome.filed == 2  # both findings counted, but...
    assert len(sink.created) == 1  # ...only one ticket actually filed
    assert finding_a.status == FindingStatus.ROUTED
    assert finding_b.status == FindingStatus.ROUTED


async def test_existing_ticket_is_reopened_not_duplicated() -> None:
    category = _category(autonomy_level=3)
    org_context = _org_context(category)
    asset = _asset()
    finding = _finding(asset, category)
    asset_repo, ownership_repo, verdict_repo, finding_repo, ticket_repo, approval_repo = _repos(
        [finding]
    )
    asset_repo._by_id[asset.id] = asset
    verdict_repo.seed(finding.id, _verdict(finding.id))
    await ticket_repo.create(
        finding_id=finding.id,
        system=TicketSystem.WEBHOOK,
        external_key="existing-1",
        assignee=None,
        cc=[],
        sla_due_at=None,
        status="open",
        created_at=_NOW,
    )
    sink = FakeSink()

    outcome = await route_findings(
        org_context,
        [finding],
        sinks={TicketSystem.WEBHOOK: sink},
        http_client=object(),  # type: ignore[arg-type]
        org_context_path=_ORG_CONTEXT_PATH,
        asset_repo=asset_repo,
        ownership_repo=ownership_repo,
        verdict_repo=verdict_repo,
        finding_repo=finding_repo,
        ticket_repo=ticket_repo,
        approval_repo=approval_repo,
        now=_NOW,
    )

    assert outcome.reopened == 1
    assert outcome.filed == 0
    assert sink.reopened == ["existing-1"]
    assert len(sink.created) == 0


async def test_non_true_positive_verdict_is_skipped() -> None:
    category = _category(autonomy_level=3)
    org_context = _org_context(category)
    asset = _asset()
    finding = _finding(asset, category)
    asset_repo, ownership_repo, verdict_repo, finding_repo, ticket_repo, approval_repo = _repos(
        [finding]
    )
    asset_repo._by_id[asset.id] = asset
    verdict_repo.seed(finding.id, _verdict(finding.id, verdict=VerdictValue.FALSE_POSITIVE))

    outcome = await route_findings(
        org_context,
        [finding],
        sinks={},
        http_client=object(),  # type: ignore[arg-type]
        org_context_path=_ORG_CONTEXT_PATH,
        asset_repo=asset_repo,
        ownership_repo=ownership_repo,
        verdict_repo=verdict_repo,
        finding_repo=finding_repo,
        ticket_repo=ticket_repo,
        approval_repo=approval_repo,
        now=_NOW,
    )

    assert outcome.skipped_no_verdict == 1
    assert outcome.shadowed == 0
    assert finding.status == FindingStatus.TRIAGED
