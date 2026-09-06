from __future__ import annotations

import uuid

from kiyooo.db.models import Evidence, ScopeDecision
from kiyooo.recon.scope import ScopeCheckResult
from kiyooo.triage.schema import VerificationRequest
from kiyooo.verify.executor import execute_verifications


class _FakeScopeGuard:
    def __init__(
        self, decision: ScopeDecision = ScopeDecision.ALLOW, reason: str = "in scope"
    ) -> None:
        self.decision = decision
        self.reason = reason
        self.calls: list[tuple[str, str, bool]] = []

    async def check(
        self, target: str, *, tool: str, is_active: bool, finding_id=None
    ) -> ScopeCheckResult:  # type: ignore[no-untyped-def]
        self.calls.append((target, tool, is_active))
        return ScopeCheckResult(self.decision, self.reason)


class _FakeRateLimiter:
    def __init__(self) -> None:
        self.acquired_hosts: list[str] = []

    async def acquire(self, host: str) -> None:
        self.acquired_hosts.append(host)


class _FakeEvidenceRepository:
    def __init__(self) -> None:
        self.added: list[Evidence] = []

    async def add(self, evidence: Evidence) -> Evidence:
        self.added.append(evidence)
        return evidence


async def _fake_runner_ok(validated) -> dict[str, object]:  # type: ignore[no-untyped-def]
    return {"status_code": 200, "body": "SSO redirect"}


async def _fake_runner_raises(validated) -> dict[str, object]:  # type: ignore[no-untyped-def]
    raise TimeoutError("connection timed out")


async def _fake_runner_leaks_secret(validated) -> dict[str, object]:  # type: ignore[no-untyped-def]
    return {"status_code": 200, "body": "config dump: AKIAABCDEFGHIJKLMNOP"}


def _request(
    tool: str = "http_probe", args: dict[str, object] | None = None
) -> VerificationRequest:
    return VerificationRequest(
        tool=tool,
        args=args or {"host": "app.example.com", "method": "GET", "path": "/login"},
        why="confirm SSO redirect",
    )


async def test_executed_request_produces_evidence_with_tool_content() -> None:
    scope_guard = _FakeScopeGuard()
    rate_limiter = _FakeRateLimiter()
    evidence_repo = _FakeEvidenceRepository()

    outcomes = await execute_verifications(
        [_request()],
        scan_run_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        finding_id=uuid.uuid4(),
        scope_guard=scope_guard,
        rate_limiter=rate_limiter,
        evidence_repo=evidence_repo,
        runners={"http_probe": _fake_runner_ok},
    )

    assert len(outcomes) == 1
    assert outcomes[0].status == "executed"
    assert outcomes[0].evidence.content_inline["body"] == "SSO redirect"
    assert len(evidence_repo.added) == 1
    assert rate_limiter.acquired_hosts == ["app.example.com"]


async def test_verification_evidence_redacts_secrets_before_persisting() -> None:
    scope_guard = _FakeScopeGuard()
    rate_limiter = _FakeRateLimiter()
    evidence_repo = _FakeEvidenceRepository()

    outcomes = await execute_verifications(
        [_request()],
        scan_run_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        finding_id=uuid.uuid4(),
        scope_guard=scope_guard,
        rate_limiter=rate_limiter,
        evidence_repo=evidence_repo,
        runners={"http_probe": _fake_runner_leaks_secret},
    )

    assert outcomes[0].evidence.redacted is True
    assert "AKIAABCDEFGHIJKLMNOP" not in str(outcomes[0].evidence.content_inline)


async def test_safety_rejection_never_reaches_scope_guard() -> None:
    scope_guard = _FakeScopeGuard()
    rate_limiter = _FakeRateLimiter()
    evidence_repo = _FakeEvidenceRepository()

    outcomes = await execute_verifications(
        [_request(tool="shell_exec", args={})],
        scan_run_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        finding_id=uuid.uuid4(),
        scope_guard=scope_guard,
        rate_limiter=rate_limiter,
        evidence_repo=evidence_repo,
        runners={},
    )

    assert outcomes[0].status == "rejected"
    assert scope_guard.calls == []  # never reached ScopeGuard at all
    assert "not one of the allowed" in outcomes[0].evidence.content_inline["reason"]


async def test_scope_guard_deny_produces_denied_outcome_no_tool_call() -> None:
    scope_guard = _FakeScopeGuard(decision=ScopeDecision.DENY, reason="out of scope")
    rate_limiter = _FakeRateLimiter()
    evidence_repo = _FakeEvidenceRepository()

    called = False

    async def _should_not_run(validated) -> dict[str, object]:  # type: ignore[no-untyped-def]
        nonlocal called
        called = True
        return {}

    outcomes = await execute_verifications(
        [_request()],
        scan_run_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        finding_id=uuid.uuid4(),
        scope_guard=scope_guard,
        rate_limiter=rate_limiter,
        evidence_repo=evidence_repo,
        runners={"http_probe": _should_not_run},
    )

    assert outcomes[0].status == "denied"
    assert outcomes[0].evidence.content_inline["reason"] == "out of scope"
    assert called is False
    assert rate_limiter.acquired_hosts == []


async def test_scope_guard_requires_confirm_is_not_sendable() -> None:
    scope_guard = _FakeScopeGuard(
        decision=ScopeDecision.REQUIRES_CONFIRM, reason="range-only match"
    )
    outcomes = await execute_verifications(
        [_request()],
        scan_run_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        finding_id=uuid.uuid4(),
        scope_guard=scope_guard,
        rate_limiter=_FakeRateLimiter(),
        evidence_repo=_FakeEvidenceRepository(),
        runners={"http_probe": _fake_runner_ok},
    )
    assert outcomes[0].status == "denied"


async def test_tool_failure_produces_failed_outcome_not_a_crash() -> None:
    outcomes = await execute_verifications(
        [_request()],
        scan_run_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        finding_id=uuid.uuid4(),
        scope_guard=_FakeScopeGuard(),
        rate_limiter=_FakeRateLimiter(),
        evidence_repo=_FakeEvidenceRepository(),
        runners={"http_probe": _fake_runner_raises},
    )
    assert outcomes[0].status == "failed"
    assert "timed out" in outcomes[0].evidence.content_inline["reason"]


async def test_max_tool_calls_caps_batch() -> None:
    requests = [_request() for _ in range(5)]
    outcomes = await execute_verifications(
        requests,
        scan_run_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        finding_id=uuid.uuid4(),
        scope_guard=_FakeScopeGuard(),
        rate_limiter=_FakeRateLimiter(),
        evidence_repo=_FakeEvidenceRepository(),
        runners={"http_probe": _fake_runner_ok},
        max_tool_calls=2,
    )
    assert len(outcomes) == 2


async def test_finding_id_threaded_into_scope_guard_check() -> None:
    scope_guard = _FakeScopeGuard()
    finding_id = uuid.uuid4()
    await execute_verifications(
        [_request()],
        scan_run_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        finding_id=finding_id,
        scope_guard=scope_guard,
        rate_limiter=_FakeRateLimiter(),
        evidence_repo=_FakeEvidenceRepository(),
        runners={"http_probe": _fake_runner_ok},
    )
    assert scope_guard.calls == [("app.example.com", "http_probe", True)]
