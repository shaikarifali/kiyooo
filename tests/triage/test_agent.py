from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from kiyooo.config import CategoryDefinition, PredicateBlock, RouteConfig, Settings
from kiyooo.db.models import (
    Asset,
    AssetType,
    Evidence,
    EvidenceKind,
    Finding,
    FindingDetector,
    FindingStatus,
    Severity,
    VerdictPassType,
    VerdictValue,
)
from kiyooo.llm.provider import LlmResponse
from kiyooo.llm.router import CostCeilingExceeded
from kiyooo.triage import agent as agent_module
from kiyooo.triage.agent import AdjudicationDeps, ProviderRegistry, adjudicate_finding
from kiyooo.triage.bundler import build_bundle, bundle_canonical_json
from kiyooo.triage.cache import compute_input_hash
from kiyooo.triage.prompts import ADJUDICATE_PROMPT_VERSION
from kiyooo.verify.executor import VerificationOutcome
from tests.triage.fakes import (
    FakeFindingRepositoryForAgent,
    FakeIdentifierVerificationRepository,
    FakeLlmCallLogRepository,
    FakeProvider,
    FakeVerdictRepository,
)

_SLA = {"critical": 1, "high": 7, "medium": 30, "low": 90, "info": 180}


def _category(**overrides: object) -> CategoryDefinition:
    defaults: dict[str, object] = dict(
        id="exposed-database",
        name="Database exposed",
        version=1,
        severity_base="high",
        applies_to=["tcp_service"],
        detect=PredicateBlock(any_of=[{"port_in": [3306]}]),
        triage_hints="test hints",
        route=RouteConfig(assign_to="appsec", sla_days=_SLA),
    )
    defaults.update(overrides)
    return CategoryDefinition.model_validate(defaults)


def _asset() -> Asset:
    now = datetime.now(UTC)
    return Asset(
        id=uuid.uuid4(),
        type=AssetType.TCP_SERVICE,
        value="10.0.0.5:3306",
        first_seen=now,
        last_seen=now,
        is_active=True,
        confidence_in_scope=1.0,
        scope_reason=None,
        attributes={},
    )


def _finding(
    asset_id: uuid.UUID,
    category_id: str = "exposed-database",
    *,
    raw_severity: Severity = Severity.MEDIUM,
) -> Finding:
    now = datetime.now(UTC)
    return Finding(
        id=uuid.uuid4(),
        scan_run_id=uuid.uuid4(),
        asset_id=asset_id,
        category_id=category_id,
        raw_severity=raw_severity,
        title="Database exposed",
        description=None,
        detector=FindingDetector.RULE,
        detector_ref="exposed-database@1",
        fingerprint=f"fp-{uuid.uuid4().hex[:8]}",
        cluster_id=uuid.uuid4(),
        status=FindingStatus.NEW,
        first_seen=now,
        last_seen=now,
    )


def _evidence(asset_id: uuid.UUID) -> Evidence:
    return Evidence(
        id=f"ev_{uuid.uuid4().hex[:8]}",
        scan_run_id=uuid.uuid4(),
        asset_id=asset_id,
        kind=EvidenceKind.PORT_BANNER,
        source_tool="fixture",
        collected_at=datetime.now(UTC),
        content_ref=None,
        content_inline={"port": 3306, "protocol": "tcp"},
        content_hash="fixture",
        size_bytes=None,
        redacted=False,
        injection_suspected=False,
    )


def _payload(
    *,
    verdict: str = "true_positive",
    confidence: float = 0.9,
    requires_verification: list | None = None,
) -> dict[str, object]:
    return {
        "verdict": verdict,
        "confidence": confidence,
        "adjusted_severity": "high",
        "reasoning": "Reachable and unauthenticated [ev_1].",
        "citations": ["ev_1"],
        "exploitability": {
            "internet_reachable": False,
            "authentication_required": False,
            "preconditions": [],
            "realistic_attack_path": "n/a",
        },
        "compensating_controls_considered": [],
        "business_impact_hypothesis": "Could expose data.",
        "remediation": {
            "summary": "Restrict access.",
            "steps": [],
            "verification": "Re-scan.",
            "estimated_effort": "small",
        },
        "requires_verification": requires_verification or [],
    }


def _response(
    content: dict[str, object] | None, *, model: str = "m", refused: bool = False
) -> LlmResponse:
    return LlmResponse(
        content=content,
        raw_text=str(content),
        model=model,
        tokens_in=100,
        tokens_out=50,
        latency_ms=10,
        refused=refused,
    )


def _deps(
    *,
    settings: Settings | None = None,
    providers: dict[str, FakeProvider] | None = None,
    verdict_repo: FakeVerdictRepository | None = None,
    spent: float = 0.0,
    verification_available: bool = False,
) -> tuple[
    AdjudicationDeps,
    FakeLlmCallLogRepository,
    FakeIdentifierVerificationRepository,
    FakeFindingRepositoryForAgent,
]:
    llm_call_log_repo = FakeLlmCallLogRepository(spent=spent)
    identifier_repo = FakeIdentifierVerificationRepository()
    finding_repo = FakeFindingRepositoryForAgent()
    deps = AdjudicationDeps(
        settings=settings or Settings(),
        providers=ProviderRegistry(providers or {}),
        verdict_repo=verdict_repo or FakeVerdictRepository(),
        llm_call_log_repo=llm_call_log_repo,
        identifier_verification_repo=identifier_repo,
        finding_repo=finding_repo,
        # Placeholder objects, never actually called — tests that need
        # verification exercised monkeypatch `execute_verifications`
        # itself, so these only need to be non-None to satisfy
        # `_verification_available`'s check.
        scope_guard=object() if verification_available else None,  # type: ignore[arg-type]
        rate_limiter=object() if verification_available else None,  # type: ignore[arg-type]
        evidence_repo=object() if verification_available else None,  # type: ignore[arg-type]
    )
    return deps, llm_call_log_repo, identifier_repo, finding_repo


async def test_bulk_only_high_confidence_no_escalation() -> None:
    asset = _asset()
    finding = _finding(asset.id)
    evidence = [_evidence(asset.id)]
    category = _category(severity_base="low", escalation_threshold=0.5)
    bulk = FakeProvider("ollama", [_response(_payload(confidence=0.95))])
    deps, _, _, finding_repo = _deps(providers={"ollama": bulk})

    result = await adjudicate_finding(
        finding,
        category,
        asset,
        evidence,
        org_name="acme",
        controls_detected=[],
        change_events=[],
        similar_past_decisions=[],
        is_new_since_last_scan=True,
        scan_run_id=finding.scan_run_id,
        deps=deps,
    )

    assert result.from_cache is False
    assert result.verdict_row.verdict == VerdictValue.TRUE_POSITIVE
    assert result.verdict_row.pass_type == VerdictPassType.BULK
    assert len(bulk.calls) == 1
    assert finding_repo.statuses[finding.id] == FindingStatus.TRIAGED


async def test_cache_hit_skips_provider_call() -> None:
    asset = _asset()
    finding = _finding(asset.id)
    evidence = [_evidence(asset.id)]
    category = _category(severity_base="low", escalation_threshold=0.5)
    settings = Settings()

    bundle = build_bundle(
        finding,
        category,
        asset,
        evidence,
        controls_detected=[],
        change_events=[],
        similar_past_decisions=[],
        is_new_since_last_scan=True,
        is_hosted_call=False,
    )
    input_hash = compute_input_hash(
        bundle_canonical_json(bundle),
        prompt_version=ADJUDICATE_PROMPT_VERSION,
        model=settings.bulk_model,
    )
    from kiyooo.db.models import Verdict

    seeded = Verdict(
        id=uuid.uuid4(),
        finding_id=finding.id,
        model=settings.bulk_model,
        model_version=settings.bulk_model,
        prompt_version=ADJUDICATE_PROMPT_VERSION,
        pass_type=VerdictPassType.BULK,
        verdict=VerdictValue.TRUE_POSITIVE,
        confidence=0.9,
        adjusted_severity=Severity.HIGH,
        reasoning="cached",
        business_impact_hypothesis="cached",
        citations=["ev_1"],
        compensating_controls=[],
        exploitability={},
        remediation={},
        input_hash=input_hash,
        tokens_in=1,
        tokens_out=1,
        cost_usd=0.0,
        latency_ms=1,
        created_at=datetime.now(UTC),
    )

    bulk = FakeProvider("ollama", [])  # no responses programmed — a call would fail the test
    deps, _, _, _ = _deps(
        settings=settings,
        providers={"ollama": bulk},
        verdict_repo=FakeVerdictRepository(seed=seeded),
    )

    result = await adjudicate_finding(
        finding,
        category,
        asset,
        evidence,
        org_name="acme",
        controls_detected=[],
        change_events=[],
        similar_past_decisions=[],
        is_new_since_last_scan=True,
        scan_run_id=finding.scan_run_id,
        deps=deps,
    )

    assert result.from_cache is True
    assert result.verdict_row is seeded
    assert bulk.calls == []


async def test_low_confidence_triggers_escalation() -> None:
    asset = _asset()
    finding = _finding(asset.id)
    evidence = [_evidence(asset.id)]
    category = _category(severity_base="low", escalation_threshold=0.8)
    bulk = FakeProvider("ollama", [_response(_payload(confidence=0.5))])
    escalation = FakeProvider("anthropic", [_response(_payload(confidence=0.95))])
    deps, _, _, _ = _deps(providers={"ollama": bulk, "anthropic": escalation})

    result = await adjudicate_finding(
        finding,
        category,
        asset,
        evidence,
        org_name="acme",
        controls_detected=[],
        change_events=[],
        similar_past_decisions=[],
        is_new_since_last_scan=True,
        scan_run_id=finding.scan_run_id,
        deps=deps,
    )

    assert result.verdict_row.pass_type == VerdictPassType.ESCALATION
    assert len(bulk.calls) == 1
    assert len(escalation.calls) == 1


async def test_always_escalate_forces_escalation_despite_high_confidence() -> None:
    asset = _asset()
    finding = _finding(asset.id)
    evidence = [_evidence(asset.id)]
    category = _category(severity_base="low", always_escalate=True, escalation_threshold=0.1)
    bulk = FakeProvider("ollama", [_response(_payload(confidence=0.99))])
    escalation = FakeProvider("anthropic", [_response(_payload(confidence=0.99))])
    deps, _, _, _ = _deps(providers={"ollama": bulk, "anthropic": escalation})

    result = await adjudicate_finding(
        finding,
        category,
        asset,
        evidence,
        org_name="acme",
        controls_detected=[],
        change_events=[],
        similar_past_decisions=[],
        is_new_since_last_scan=True,
        scan_run_id=finding.scan_run_id,
        deps=deps,
    )

    assert result.verdict_row.pass_type == VerdictPassType.ESCALATION
    assert len(escalation.calls) == 1


async def test_local_only_category_never_calls_hosted_provider() -> None:
    asset = _asset()
    finding = _finding(asset.id)
    evidence = [_evidence(asset.id)]
    category = _category(
        severity_base="low", redaction_profile="local_only", escalation_threshold=0.99
    )
    bulk = FakeProvider("ollama", [_response(_payload(confidence=0.1))])
    # No "anthropic" provider registered at all — if the agent tried to
    # reach it, ProviderRegistry.get would raise.
    deps, _, _, _ = _deps(providers={"ollama": bulk})

    result = await adjudicate_finding(
        finding,
        category,
        asset,
        evidence,
        org_name="acme",
        controls_detected=[],
        change_events=[],
        similar_past_decisions=[],
        is_new_since_last_scan=True,
        scan_run_id=finding.scan_run_id,
        deps=deps,
    )

    assert result.verdict_row.pass_type == VerdictPassType.BULK
    assert len(bulk.calls) == 1


async def test_requires_verification_forces_needs_human_without_escalating() -> None:
    asset = _asset()
    finding = _finding(asset.id)
    evidence = [_evidence(asset.id)]
    category = _category(severity_base="low", escalation_threshold=0.1)
    payload = _payload(
        confidence=0.99,
        requires_verification=[{"tool": "tcp_banner", "args": {}, "why": "confirm auth"}],
    )
    bulk = FakeProvider("ollama", [_response(payload)])
    deps, _, _, _ = _deps(providers={"ollama": bulk})

    result = await adjudicate_finding(
        finding,
        category,
        asset,
        evidence,
        org_name="acme",
        controls_detected=[],
        change_events=[],
        similar_past_decisions=[],
        is_new_since_last_scan=True,
        scan_run_id=finding.scan_run_id,
        deps=deps,
    )

    assert result.verdict_row.verdict == VerdictValue.NEEDS_HUMAN
    assert len(bulk.calls) == 1  # no escalation attempted


async def test_hosted_bulk_refusal_falls_back_to_local() -> None:
    asset = _asset()
    finding = _finding(asset.id)
    evidence = [_evidence(asset.id)]
    category = _category(severity_base="low", escalation_threshold=0.1)
    settings = Settings(llm_provider="anthropic", bulk_model="claude-sonnet-5")
    hosted = FakeProvider("anthropic", [_response(None, refused=True)])
    local_fallback = FakeProvider("ollama", [_response(_payload(confidence=0.95))])
    deps, _, _, _ = _deps(
        settings=settings, providers={"anthropic": hosted, "ollama": local_fallback}
    )

    result = await adjudicate_finding(
        finding,
        category,
        asset,
        evidence,
        org_name="acme",
        controls_detected=[],
        change_events=[],
        similar_past_decisions=[],
        is_new_since_last_scan=True,
        scan_run_id=finding.scan_run_id,
        deps=deps,
    )

    assert len(hosted.calls) == 1
    assert len(local_fallback.calls) == 1
    assert result.verdict_row.verdict == VerdictValue.TRUE_POSITIVE


async def test_both_passes_fail_produces_synthetic_needs_human() -> None:
    asset = _asset()
    finding = _finding(asset.id)
    evidence = [_evidence(asset.id)]
    category = _category(severity_base="low", escalation_threshold=0.1)
    settings = Settings(llm_provider="anthropic", bulk_model="claude-sonnet-5")
    hosted = FakeProvider("anthropic", [_response(None, refused=True)])
    local_fallback = FakeProvider("ollama", [_response(None, refused=True)])
    deps, _, _, _ = _deps(
        settings=settings, providers={"anthropic": hosted, "ollama": local_fallback}
    )

    result = await adjudicate_finding(
        finding,
        category,
        asset,
        evidence,
        org_name="acme",
        controls_detected=[],
        change_events=[],
        similar_past_decisions=[],
        is_new_since_last_scan=True,
        scan_run_id=finding.scan_run_id,
        deps=deps,
    )

    assert result.verdict_row.verdict == VerdictValue.NEEDS_HUMAN


async def test_cost_ceiling_exceeded_raises_before_any_call() -> None:
    asset = _asset()
    finding = _finding(asset.id)
    evidence = [_evidence(asset.id)]
    category = _category(severity_base="low")
    bulk = FakeProvider("ollama", [])
    deps, _, _, _ = _deps(providers={"ollama": bulk}, spent=100.0)

    with pytest.raises(CostCeilingExceeded):
        await adjudicate_finding(
            finding,
            category,
            asset,
            evidence,
            org_name="acme",
            controls_detected=[],
            change_events=[],
            similar_past_decisions=[],
            is_new_since_last_scan=True,
            scan_run_id=finding.scan_run_id,
            deps=deps,
        )
    assert bulk.calls == []


async def test_false_positive_on_critical_forces_needs_human_status() -> None:
    asset = _asset()
    finding = _finding(asset.id)
    finding.raw_severity = Severity.CRITICAL
    evidence = [_evidence(asset.id)]
    category = _category(severity_base="critical", escalation_threshold=0.1)
    fp_payload = _payload(verdict="false_positive", confidence=0.9)
    bulk = FakeProvider("ollama", [_response(fp_payload)])
    escalation = FakeProvider("anthropic", [_response(fp_payload)])
    deps, _, _, finding_repo = _deps(providers={"ollama": bulk, "anthropic": escalation})

    result = await adjudicate_finding(
        finding,
        category,
        asset,
        evidence,
        org_name="acme",
        controls_detected=[],
        change_events=[],
        similar_past_decisions=[],
        is_new_since_last_scan=True,
        scan_run_id=finding.scan_run_id,
        deps=deps,
    )

    assert result.verdict_row.verdict == VerdictValue.NEEDS_HUMAN
    assert finding_repo.statuses[finding.id] == FindingStatus.TRIAGING


def _verification_outcome(asset_id: uuid.UUID) -> VerificationOutcome:
    from kiyooo.triage.schema import VerificationRequest

    request = VerificationRequest(
        tool="http_probe",
        args={"host": "app.example.com", "method": "GET", "path": "/login"},
        why="confirm SSO redirect",
    )
    outcome_evidence = Evidence(
        id=f"ev_verify_{uuid.uuid4().hex[:8]}",
        scan_run_id=uuid.uuid4(),
        asset_id=asset_id,
        kind=EvidenceKind.VERIFICATION_RESULT,
        source_tool="verify:http_probe",
        collected_at=datetime.now(UTC),
        content_ref=None,
        content_inline={"status_code": 302, "header": {"location": "https://login.example.com"}},
        content_hash="fixture",
        size_bytes=None,
        redacted=False,
        injection_suspected=False,
    )
    return VerificationOutcome(request=request, status="executed", evidence=outcome_evidence)


async def test_verification_round_resolves_needs_human_to_confident_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stage 6's own DoD example: a needs_human-on-evidence-alone finding
    ("is this login page SSO-backed?") gets resolved after verification.
    """
    asset = _asset()
    finding = _finding(asset.id)
    evidence = [_evidence(asset.id)]
    category = _category(severity_base="low", escalation_threshold=0.1)

    round_one = _payload(
        confidence=0.4,
        requires_verification=[
            {"tool": "http_probe", "args": {"host": "app.example.com"}, "why": "confirm SSO"}
        ],
    )
    round_two = _payload(confidence=0.95, requires_verification=[])
    bulk = FakeProvider("ollama", [_response(round_one), _response(round_two)])
    deps, _, _, _ = _deps(providers={"ollama": bulk}, verification_available=True)

    executor_calls = 0

    async def fake_execute_verifications(requests, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal executor_calls
        executor_calls += 1
        return [_verification_outcome(asset.id)]

    monkeypatch.setattr(agent_module, "execute_verifications", fake_execute_verifications)

    result = await adjudicate_finding(
        finding,
        category,
        asset,
        evidence,
        org_name="acme",
        controls_detected=[],
        change_events=[],
        similar_past_decisions=[],
        is_new_since_last_scan=True,
        scan_run_id=finding.scan_run_id,
        deps=deps,
    )

    assert executor_calls == 1
    assert len(bulk.calls) == 2  # one call per adjudication round
    assert result.verdict_row.verdict == VerdictValue.TRUE_POSITIVE


async def test_verification_rounds_exhausted_forces_needs_human(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset = _asset()
    finding = _finding(asset.id)
    evidence = [_evidence(asset.id)]
    category = _category(severity_base="low", escalation_threshold=0.1)

    still_wants_more = _payload(
        confidence=0.4,
        requires_verification=[
            {"tool": "http_probe", "args": {"host": "app.example.com"}, "why": "still unsure"}
        ],
    )
    bulk = FakeProvider("ollama", [_response(still_wants_more) for _ in range(3)])
    deps, _, _, _ = _deps(providers={"ollama": bulk}, verification_available=True)

    executor_calls = 0

    async def fake_execute_verifications(requests, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal executor_calls
        executor_calls += 1
        return [_verification_outcome(asset.id)]

    monkeypatch.setattr(agent_module, "execute_verifications", fake_execute_verifications)

    result = await adjudicate_finding(
        finding,
        category,
        asset,
        evidence,
        org_name="acme",
        controls_detected=[],
        change_events=[],
        similar_past_decisions=[],
        is_new_since_last_scan=True,
        scan_run_id=finding.scan_run_id,
        deps=deps,
    )

    assert executor_calls == 2  # _MAX_VERIFICATION_ROUNDS
    assert len(bulk.calls) == 3  # initial + 2 verification rounds
    assert result.verdict_row.verdict == VerdictValue.NEEDS_HUMAN
