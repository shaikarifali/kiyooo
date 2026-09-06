from __future__ import annotations

import uuid
from datetime import UTC, datetime

import structlog

from kiyooo.db.models import Asset, AssetType, EvidenceKind, ScanRunStatus
from kiyooo.recon.base import ParsedEvidence, ReconStage, ScanProfile
from kiyooo.recon.orchestrator import Orchestrator
from kiyooo.recon.scope import ScopeGuard
from tests.recon.factories import make_asset, make_scope
from tests.recon.fakes import FakeEvidenceWriter, FakeScanRunRepository, make_fake_adapter_class


def _orchestrator(
    scope_guard: ScopeGuard,
    *,
    adapter_classes: list[type],
    profile: ScanProfile = ScanProfile.DEEP,
    dry_run: bool = False,
    max_retries: int = 1,
    backoff_base_s: float = 0.0,
) -> tuple[Orchestrator, FakeScanRunRepository, FakeEvidenceWriter]:
    scan_run_repo = FakeScanRunRepository()
    evidence_writer = FakeEvidenceWriter()
    orch = Orchestrator(
        scan_run_repo=scan_run_repo,
        evidence_writer=evidence_writer,
        scope_guard=scope_guard,
        profile=profile,
        dry_run=dry_run,
        logger=structlog.get_logger(),
        adapter_classes=adapter_classes,
        max_retries=max_retries,
        backoff_base_s=backoff_base_s,
    )
    return orch, scan_run_repo, evidence_writer


async def test_partial_failure_does_not_kill_the_run(audit_log_repo) -> None:
    scope_guard = ScopeGuard(
        make_scope(), cli_active_flag=False, audit_log_repo=audit_log_repo, scan_run_id=None
    )
    ok_adapter = make_fake_adapter_class(
        "ok-tool", ReconStage.DISCOVER, {AssetType.DOMAIN}, is_active=False
    )
    crashing_adapter = make_fake_adapter_class(
        "crashing-tool",
        ReconStage.DISCOVER,
        {AssetType.DOMAIN},
        is_active=False,
        should_raise=True,
    )
    orch, scan_run_repo, _ = _orchestrator(
        scope_guard, adapter_classes=[ok_adapter, crashing_adapter], profile=ScanProfile.PASSIVE
    )

    seeds = [make_asset(AssetType.DOMAIN, "example.com")]
    outcomes = await orch.run(seeds, scan_run_id=uuid.uuid4())

    by_tool = {o.tool: o for o in outcomes}
    assert by_tool["ok-tool"].ok is True
    assert by_tool["crashing-tool"].ok is False
    assert "blew up" in (by_tool["crashing-tool"].error or "")
    # the run itself completed despite one adapter dying
    assert scan_run_repo.status_history[-1] == ScanRunStatus.COMPLETED


async def test_failing_adapter_is_retried_then_marked_failed(audit_log_repo) -> None:
    scope_guard = ScopeGuard(
        make_scope(), cli_active_flag=False, audit_log_repo=audit_log_repo, scan_run_id=None
    )
    failing = make_fake_adapter_class(
        "failing-tool", ReconStage.DISCOVER, {AssetType.DOMAIN}, is_active=False, should_fail=True
    )
    orch, _, _ = _orchestrator(
        scope_guard, adapter_classes=[failing], profile=ScanProfile.PASSIVE, max_retries=2
    )

    seeds = [make_asset(AssetType.DOMAIN, "example.com")]
    outcomes = await orch.run(seeds, scan_run_id=uuid.uuid4())

    assert len(outcomes) == 1
    assert outcomes[0].ok is False
    assert outcomes[0].error == "simulated failure"
    # 1 initial attempt + 2 retries = 3 calls
    assert failing.run_call_count == 3


async def test_denied_targets_never_reach_run(audit_log_repo) -> None:
    scope_guard = ScopeGuard(
        make_scope(domains=["in-scope.example.com"]),
        cli_active_flag=False,
        audit_log_repo=audit_log_repo,
        scan_run_id=None,
    )
    adapter_cls = make_fake_adapter_class(
        "discover-tool", ReconStage.DISCOVER, {AssetType.DOMAIN}, is_active=False
    )
    orch, _, _ = _orchestrator(
        scope_guard, adapter_classes=[adapter_cls], profile=ScanProfile.PASSIVE
    )

    seeds = [make_asset(AssetType.DOMAIN, "out-of-scope.example.org")]
    outcomes = await orch.run(seeds, scan_run_id=uuid.uuid4())

    assert adapter_cls.run_call_count == 0
    assert outcomes[0].denied_targets == 1
    assert outcomes[0].allowed_targets == 0
    assert outcomes[0].ok is True  # nothing to do isn't a failure


async def test_dry_run_never_calls_run_and_describes_instead(audit_log_repo) -> None:
    scope_guard = ScopeGuard(
        make_scope(), cli_active_flag=False, audit_log_repo=audit_log_repo, scan_run_id=None
    )
    adapter_cls = make_fake_adapter_class(
        "naabu-like", ReconStage.PORTSCAN, {AssetType.DOMAIN}, is_active=True
    )
    orch, _, _ = _orchestrator(
        scope_guard, adapter_classes=[adapter_cls], profile=ScanProfile.DEEP, dry_run=True
    )

    seeds = [make_asset(AssetType.DOMAIN, "example.com")]
    outcomes = await orch.run(seeds, scan_run_id=uuid.uuid4())

    assert adapter_cls.run_call_count == 0
    assert outcomes[0].dry_run is True
    assert "naabu-like" in (outcomes[0].description or "")


async def test_discovered_assets_flow_into_the_next_stage(audit_log_repo) -> None:
    scope_guard = ScopeGuard(
        make_scope(domains=["example.com"], wildcards=["*.example.com"]),
        cli_active_flag=False,
        audit_log_repo=audit_log_repo,
        scan_run_id=None,
    )
    now = datetime.now(UTC)
    discovered = make_asset(AssetType.SUBDOMAIN, "api.example.com")
    discover_adapter = make_fake_adapter_class(
        "subfinder-like",
        ReconStage.DISCOVER,
        {AssetType.DOMAIN},
        produces={AssetType.SUBDOMAIN},
        is_active=False,
        evidence_to_return=[
            ParsedEvidence(
                kind=EvidenceKind.DNS_RECORD,
                asset_type=AssetType.SUBDOMAIN,
                asset_value="api.example.com",
                content={"host": "api.example.com"},
                collected_at=now,
            )
        ],
    )
    resolve_adapter = make_fake_adapter_class(
        "dnsx-like", ReconStage.RESOLVE, {AssetType.SUBDOMAIN}, is_active=False
    )
    orch, _, evidence_writer = _orchestrator(
        scope_guard,
        adapter_classes=[discover_adapter, resolve_adapter],
        profile=ScanProfile.PASSIVE,
    )

    async def fake_write_many(parsed: list[ParsedEvidence], *, source_tool: str) -> list[Asset]:
        evidence_writer.written.append((source_tool, parsed))
        return [discovered]

    evidence_writer.write_many = fake_write_many  # type: ignore[method-assign]

    seeds = [make_asset(AssetType.DOMAIN, "example.com")]
    await orch.run(seeds, scan_run_id=uuid.uuid4())

    resolved_targets = resolve_adapter.received_targets
    assert any(a.value == "api.example.com" for a in resolved_targets)
