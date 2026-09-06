"""Verification tool executor — takes a verdict's
`requires_verification[]`, validates each entry (`verify/safety.py`),
clears it through `ScopeGuard` exactly like a Stage 1 active adapter would,
rate-limits, executes, and returns new `Evidence` rows with fresh ids.

Every outcome — executed, rejected by `safety.py`, denied by `ScopeGuard`,
or a tool that failed at runtime — becomes an `Evidence` row, not just the
successes. That's what makes "the agent is told why" (this stage's DoD)
actually work: the next re-adjudication round's bundle includes this
evidence the same way it includes anything else, no separate side-channel
needed for rejections.

A request this function never reaches `ScopeGuard` for (a `safety.py`
rejection) is not a `ScopeGuard` decision and has no `audit_log` row of its
own — invariant #2 only requires an audit trail for things that could have
sent a packet, and a rejected request never gets that close.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from kiyooo.db.models import Evidence, EvidenceKind
from kiyooo.normalize.injection import scan_evidence_content
from kiyooo.normalize.redact import redact_content
from kiyooo.verify.safety import VerificationRejected, validate_request
from kiyooo.verify.tools import (
    cert_chain,
    dns_resolve,
    http_probe,
    nuclei_single,
    tcp_banner,
    tls_handshake,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from uuid import UUID

    from kiyooo.db.repo.evidence import EvidenceRepository
    from kiyooo.recon.base import HostRateLimiter
    from kiyooo.recon.scope import ScopeGuard
    from kiyooo.triage.schema import VerificationRequest
    from kiyooo.verify.safety import ValidatedRequest

_DEFAULT_MAX_TOOL_CALLS = 10
_TOOL_TIMEOUT_S = 15.0

_RUNNERS: dict[str, Callable[[ValidatedRequest], Awaitable[dict[str, object]]]] = {
    "http_probe": http_probe.run,
    "tcp_banner": tcp_banner.run,
    "tls_handshake": tls_handshake.run,
    "dns_resolve": dns_resolve.run,
    "cert_chain": cert_chain.run,
    "nuclei_single": nuclei_single.run,
}


@dataclass(frozen=True, slots=True)
class VerificationOutcome:
    request: VerificationRequest
    status: str  # "executed" | "rejected" | "denied" | "failed"
    evidence: Evidence


def _write_evidence(
    *, scan_run_id: UUID, asset_id: UUID, tool: str, content: dict[str, object]
) -> Evidence:
    # Invariant #7: a verification probe fetches attacker-controlled
    # content (an HTTP response body, a cert CN) just like a Stage 1
    # adapter does — redact before hashing/storing, same as there.
    redacted_content, secrets_found = redact_content(content)
    if secrets_found:
        redacted_content = {
            **redacted_content,
            "_redacted_secrets": [
                {"secret_type": s.secret_type, "partial_hash": s.partial_hash}
                for s in secrets_found
            ],
        }

    content_json = json.dumps(redacted_content, sort_keys=True, default=str)
    return Evidence(
        id=f"ev_verify_{uuid.uuid4().hex[:12]}",
        scan_run_id=scan_run_id,
        asset_id=asset_id,
        kind=EvidenceKind.VERIFICATION_RESULT,
        source_tool=f"verify:{tool}",
        collected_at=datetime.now(UTC),
        content_ref=None,
        content_inline=redacted_content,
        content_hash=hashlib.sha256(content_json.encode()).hexdigest(),
        size_bytes=len(content_json),
        redacted=bool(secrets_found),
        injection_suspected=scan_evidence_content(redacted_content),
    )


async def _execute_one(
    request: VerificationRequest,
    *,
    scan_run_id: UUID,
    asset_id: UUID,
    finding_id: UUID,
    scope_guard: ScopeGuard,
    rate_limiter: HostRateLimiter,
    evidence_repo: EvidenceRepository,
    runners: dict[str, Callable[[ValidatedRequest], Awaitable[dict[str, object]]]],
) -> VerificationOutcome:
    try:
        validated = validate_request(request)
    except VerificationRejected as exc:
        evidence = await evidence_repo.add(
            _write_evidence(
                scan_run_id=scan_run_id,
                asset_id=asset_id,
                tool=request.tool,
                content={"status": "rejected", "reason": str(exc), "requested_by_model": True},
            )
        )
        return VerificationOutcome(request=request, status="rejected", evidence=evidence)

    scope_result = await scope_guard.check(
        validated.target, tool=validated.tool, is_active=True, finding_id=finding_id
    )
    if not scope_result.sendable:
        evidence = await evidence_repo.add(
            _write_evidence(
                scan_run_id=scan_run_id,
                asset_id=asset_id,
                tool=validated.tool,
                content={
                    "status": "denied",
                    "reason": scope_result.reason,
                    "requested_by_model": True,
                },
            )
        )
        return VerificationOutcome(request=request, status="denied", evidence=evidence)

    host = validated.target.split(":")[0]
    await rate_limiter.acquire(host)

    runner = runners[validated.tool]
    try:
        content = await asyncio.wait_for(runner(validated), timeout=_TOOL_TIMEOUT_S)
        status = "executed"
    except Exception as exc:  # noqa: BLE001 -- a failed probe is a result, not a crash
        content = {"status": "failed", "reason": str(exc), "requested_by_model": True}
        status = "failed"

    evidence = await evidence_repo.add(
        _write_evidence(
            scan_run_id=scan_run_id, asset_id=asset_id, tool=validated.tool, content=content
        )
    )
    return VerificationOutcome(request=request, status=status, evidence=evidence)


async def execute_verifications(
    requests: list[VerificationRequest],
    *,
    scan_run_id: UUID,
    asset_id: UUID,
    finding_id: UUID,
    scope_guard: ScopeGuard,
    rate_limiter: HostRateLimiter,
    evidence_repo: EvidenceRepository,
    max_tool_calls: int = _DEFAULT_MAX_TOOL_CALLS,
    runners: dict[str, Callable[[ValidatedRequest], Awaitable[dict[str, object]]]] | None = None,
) -> list[VerificationOutcome]:
    """Caps at `max_tool_calls` per call — `triage/agent.py`'s own
    max-2-re-adjudication-round cap bounds the total
    across a finding's whole verification process without this function
    needing to track state across calls itself.

    `runners` defaults to the real tools (`_RUNNERS`) — tests override it
    with fakes so this function's own orchestration logic (validate ->
    ScopeGuard -> rate limit -> execute -> evidence) is exercised with no
    live network call, ever.
    """
    active_runners = runners if runners is not None else _RUNNERS
    outcomes: list[VerificationOutcome] = []
    for request in requests[:max_tool_calls]:
        outcomes.append(
            await _execute_one(
                request,
                scan_run_id=scan_run_id,
                asset_id=asset_id,
                finding_id=finding_id,
                scope_guard=scope_guard,
                rate_limiter=rate_limiter,
                evidence_repo=evidence_repo,
                runners=active_runners,
            )
        )
    return outcomes
