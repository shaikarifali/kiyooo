"""The adjudication loop.

Steps, mapped to what runs here:
  1. Deterministic prefilter    -> already done upstream: a finding only
                                    reaches this module after Stage 4's
                                    `detect/engine.py` matched a category
                                    and cleared suppression.
  2. Cache lookup on input_hash -> checked at the top of every round
                                    (§4.3's step 2 repeats each time the
                                    bundle changes) — a hit returns a prior
                                    fully-resolved verdict and skips
                                    everything below it.
  3. Bulk model call            -> `_run_pass`, one schema-retry.
  4. Validator                  -> `triage/validator.py`'s cross-checks +
                                    identifier verification.
  5. requires_verification      -> `verify/executor.py` (Stage 6): each
                                    request is validated, cleared through
                                    ScopeGuard, executed, and its result
                                    (success, rejection, or denial) becomes
                                    new evidence for a re-adjudication round
                                    — capped at `_MAX_VERIFICATION_ROUNDS`.
                                    Without verification deps configured
                                    (`deps.scope_guard`/`rate_limiter`/
                                    `evidence_repo` all `None` — the eval
                                    harness's case, which must never send
                                    real packets), this forces `needs_human`
                                    exactly as it did before Stage 6.
  6. Escalation                 -> `llm/router.py`'s `needs_escalation()`.
  7. Persist + route            -> `Verdict` row + `Finding.status`.

A `local_only` category never reaches a hosted provider at
any point in this loop — `_model_for` pins both bulk and escalation to the
same local model for such a category, so a low-confidence result stays
`needs_human` rather than escalating to a provider that must never see
this evidence.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from kiyooo.db.models import (
    FindingStatus,
    IdentifierKind,
    IdentifierSource,
    IdentifierStatus,
    IdentifierVerification,
    LlmCallLog,
    LlmCallPurpose,
    Severity,
    Verdict,
    VerdictPassType,
    VerdictValue,
)
from kiyooo.llm.cost import calculate_cost, is_local_provider
from kiyooo.llm.provider import Message, ProviderError
from kiyooo.llm.router import ModelSelection, check_cost_ceiling, needs_escalation, select_model
from kiyooo.triage.bundler import build_bundle, bundle_canonical_json
from kiyooo.triage.cache import compute_input_hash, lookup_cached_verdict
from kiyooo.triage.prompts import ADJUDICATE_PROMPT_VERSION, load_adjudicate_prompt
from kiyooo.triage.schema import Exploitability, Remediation, VerdictSchema, verdict_json_schema
from kiyooo.triage.validator import (
    looks_like_refusal,
    run_cross_checks,
    validate_schema,
    verify_identifiers,
)
from kiyooo.verify.executor import execute_verifications

if TYPE_CHECKING:
    from uuid import UUID

    from kiyooo.config import CategoryDefinition, Settings
    from kiyooo.db.models import Asset, ChangeEvent, Control, Evidence, Finding
    from kiyooo.db.repo.evidence import EvidenceRepository
    from kiyooo.db.repo.finding import FindingRepository
    from kiyooo.db.repo.identifier_verification import IdentifierVerificationRepository
    from kiyooo.db.repo.llm_call_log import LlmCallLogRepository
    from kiyooo.db.repo.model_pin import ModelPinRepository
    from kiyooo.db.repo.verdict import VerdictRepository
    from kiyooo.llm.provider import LlmProvider, LlmResponse
    from kiyooo.recon.base import HostRateLimiter
    from kiyooo.recon.scope import ScopeGuard
    from kiyooo.skills.loader import SelectedSkill
    from kiyooo.triage.bundler import SimilarPastDecision
    from kiyooo.triage.validator import NvdLookup

_MAX_SCHEMA_RETRIES = 1
_MAX_VERIFICATION_ROUNDS = 2  # the design step 5: "re-adjudicate (max 2 loops)"
_FORCE_HUMAN_IDENTIFIER_KINDS = frozenset(
    {IdentifierKind.CVE, IdentifierKind.CWE, IdentifierKind.CVSS_VECTOR, IdentifierKind.HOSTNAME}
)


class ProviderRegistry:
    """Name -> `LlmProvider` instance. Built once per run by the caller
    (CLI) from whatever credentials are configured; `agent.py` never
    imports a concrete provider itself.
    """

    def __init__(self, providers: dict[str, LlmProvider]) -> None:
        self._providers = providers

    def get(self, name: str) -> LlmProvider:
        provider = self._providers.get(name)
        if provider is None:
            raise ProviderError(f"no provider configured for {name!r}")
        return provider


@dataclass(frozen=True, slots=True)
class AdjudicationDeps:
    settings: Settings
    providers: ProviderRegistry
    verdict_repo: VerdictRepository
    llm_call_log_repo: LlmCallLogRepository
    identifier_verification_repo: IdentifierVerificationRepository
    finding_repo: FindingRepository
    nvd_lookup: NvdLookup | None = None
    # Stage 6 verification deps — all-or-nothing. `None` (the default)
    # means "no executor available," and a requires_verification request
    # forces needs_human exactly as it did before this stage existed. The
    # eval harness deliberately never sets these: it must never send a real
    # packet (CLAUDE.md's testing rule extends in spirit to anything that
    # isn't a deliberate, human-run scan).
    scope_guard: ScopeGuard | None = None
    rate_limiter: HostRateLimiter | None = None
    evidence_repo: EvidenceRepository | None = None
    # `None` (the default) means "no pin management wired up here" —
    # `_model_for` falls back to `Settings.bulk_model`/`escalation_model`
    # exactly as before this existed. The eval harness deliberately never
    # sets this either, for the same "never let a live-DB dependency creep
    # into an offline harness" reason `scope_guard`/`rate_limiter` don't.
    model_pin_repo: ModelPinRepository | None = None


@dataclass(frozen=True, slots=True)
class AdjudicationResult:
    verdict_row: Verdict
    from_cache: bool


@dataclass(frozen=True, slots=True)
class _RoundResult:
    verdict_schema: VerdictSchema
    selection: ModelSelection
    bundle: dict[str, object]
    response: LlmResponse
    pass_type: VerdictPassType
    needs_human_forced: bool
    input_hash: str


async def _model_for(
    pass_type: VerdictPassType,
    category: CategoryDefinition,
    settings: Settings,
    model_pin_repo: ModelPinRepository | None,
) -> ModelSelection:
    selection = await select_model(pass_type, settings, model_pin_repo)
    if category.redaction_profile == "local_only" and not is_local_provider(selection.provider):
        return ModelSelection(provider=settings.llm_provider, model=settings.bulk_model)
    return selection


def _synthetic_needs_human(raw_severity: Severity, reason: str) -> VerdictSchema:
    return VerdictSchema(
        verdict="needs_human",
        confidence=0.0,
        adjusted_severity=raw_severity.value,
        reasoning=reason,
        citations=[],
        exploitability=Exploitability(
            internet_reachable=False,
            authentication_required=False,
            preconditions=[],
            realistic_attack_path="unknown",
        ),
        business_impact_hypothesis="unknown — adjudication did not complete",
        remediation=Remediation(
            summary="pending human review", verification="n/a", estimated_effort="small"
        ),
    )


async def _call_once(
    provider: LlmProvider,
    model: str,
    system_prompt: str,
    bundle: dict[str, object],
    schema: dict[str, object],
    *,
    error_text: str | None,
) -> tuple[LlmResponse, VerdictSchema | None, str | None]:
    user_content = bundle_canonical_json({"evidence_bundle": bundle})
    if error_text:
        user_content = (
            "Your previous response did not match the required schema:\n"
            f"{error_text}\n\nReturn ONLY a corrected structured response for the bundle "
            f"below.\n\n{user_content}"
        )
    messages = [
        Message(role="system", content=system_prompt),
        Message(role="user", content=user_content),
    ]
    response = await provider.complete(messages, schema=schema, model=model)
    if response.refused or (response.content is None and looks_like_refusal(response.raw_text)):
        return response, None, "refused"
    verdict, error = validate_schema(response.content)
    return response, verdict, error


def _build_call_log(
    response: LlmResponse,
    *,
    provider_name: str,
    model: str,
    pass_type: VerdictPassType,
    finding_id: UUID,
    scan_run_id: UUID,
    system_prompt_hash: str,
    refused: bool,
) -> LlmCallLog:
    return LlmCallLog(
        scan_run_id=scan_run_id,
        finding_id=finding_id,
        purpose=LlmCallPurpose.ADJUDICATE,
        provider=provider_name,
        model=response.model or model,
        model_digest=None,
        prompt_version=ADJUDICATE_PROMPT_VERSION,
        system_prompt_hash=system_prompt_hash,
        # The full bundle already lives in `evidence`/`Finding` rows — this
        # logs the shape of the exchange for audit, not a second copy of
        # attacker-controlled content.
        messages={"pass_type": pass_type.value, "note": "see finding_id for the evidence bundle"},
        raw_response=response.raw_text,
        refused=refused,
        refusal_reason=response.refusal_reason,
        tokens_in=response.tokens_in,
        tokens_out=response.tokens_out,
        cost_usd=calculate_cost(
            provider_name,
            response.model or model,
            tokens_in=response.tokens_in,
            tokens_out=response.tokens_out,
        ),
        latency_ms=response.latency_ms,
        created_at=datetime.now(UTC),
    )


async def _run_pass(
    deps: AdjudicationDeps,
    pass_type: VerdictPassType,
    selection: ModelSelection,
    system_prompt: str,
    bundle: dict[str, object],
    *,
    finding_id: UUID,
    scan_run_id: UUID,
) -> tuple[VerdictSchema | None, LlmResponse]:
    provider = deps.providers.get(selection.provider)
    schema = verdict_json_schema()
    prompt_hash = hashlib.sha256(system_prompt.encode()).hexdigest()

    response, verdict, error = await _call_once(
        provider, selection.model, system_prompt, bundle, schema, error_text=None
    )
    retries = 0
    while verdict is None and error != "refused" and retries < _MAX_SCHEMA_RETRIES:
        retries += 1
        response, verdict, error = await _call_once(
            provider, selection.model, system_prompt, bundle, schema, error_text=error
        )

    await deps.llm_call_log_repo.add(
        _build_call_log(
            response,
            provider_name=selection.provider,
            model=selection.model,
            pass_type=pass_type,
            finding_id=finding_id,
            scan_run_id=scan_run_id,
            system_prompt_hash=prompt_hash,
            refused=error == "refused",
        )
    )
    return verdict, response


async def _verify_and_flag(
    verdict: VerdictSchema,
    bundle: dict[str, object],
    *,
    finding_id: UUID,
    deps: AdjudicationDeps,
    known_identities: set[str],
) -> bool:
    """Persists every identifier check and reports whether any of them
    forces human review — a hallucinated CVE/CWE/CVSS/hostname, per
    the design's per-identifier action table. A version mismatch alone never
    forces review on its own; `run_cross_checks` already downgrades
    confidence for thinly-cited high-confidence verdicts generally.
    """
    results = await verify_identifiers(
        verdict, bundle, known_identities=known_identities, nvd_lookup=deps.nvd_lookup
    )
    now = datetime.now(UTC)
    force_human = False
    for result in results:
        await deps.identifier_verification_repo.add(
            IdentifierVerification(
                finding_id=finding_id,
                kind=result.kind,
                claimed_value=result.claimed_value,
                source=IdentifierSource.MODEL,
                resolved=result.resolved,
                authority=result.authority,
                resolved_value=result.resolved_value,
                status=result.status,
                checked_at=now,
            )
        )
        if (
            result.status in (IdentifierStatus.HALLUCINATED, IdentifierStatus.MISMATCH)
            and result.kind in _FORCE_HUMAN_IDENTIFIER_KINDS
        ):
            force_human = True
    return force_human


async def _run_adjudication_round(
    finding: Finding,
    category: CategoryDefinition,
    asset: Asset,
    evidence: list[Evidence],
    *,
    system_prompt: str,
    known_identities: set[str],
    controls_detected: list[Control],
    change_events: list[ChangeEvent],
    similar_past_decisions: list[SimilarPastDecision],
    is_new_since_last_scan: bool,
    scan_run_id: UUID,
    deps: AdjudicationDeps,
    skills: list[SelectedSkill],
) -> Verdict | _RoundResult:
    """One full bulk(+escalation) pass over the given evidence set. Returns
    a cached `Verdict` row directly on a cache hit, or a `_RoundResult` for
    the caller to either persist or send through another verification
    round with more evidence.
    """
    raw_severity = finding.raw_severity

    bulk_selection = await _model_for(
        VerdictPassType.BULK, category, deps.settings, deps.model_pin_repo
    )
    bulk_bundle = build_bundle(
        finding,
        category,
        asset,
        evidence,
        controls_detected=controls_detected,
        change_events=change_events,
        similar_past_decisions=similar_past_decisions,
        is_new_since_last_scan=is_new_since_last_scan,
        is_hosted_call=not is_local_provider(bulk_selection.provider),
        skills=skills,
    )
    input_hash = compute_input_hash(
        bundle_canonical_json(bulk_bundle),
        prompt_version=ADJUDICATE_PROMPT_VERSION,
        model=bulk_selection.model,
    )

    cached = await lookup_cached_verdict(deps.verdict_repo, input_hash)
    if cached is not None:
        return cached

    await check_cost_ceiling(
        deps.llm_call_log_repo, scan_run_id, deps.settings.max_cost_usd_per_run
    )

    bulk_verdict, bulk_response = await _run_pass(
        deps,
        VerdictPassType.BULK,
        bulk_selection,
        system_prompt,
        bulk_bundle,
        finding_id=finding.id,
        scan_run_id=scan_run_id,
    )

    final_selection = bulk_selection
    final_bundle = bulk_bundle
    final_response = bulk_response
    pass_type = VerdictPassType.BULK

    if bulk_verdict is None and not is_local_provider(bulk_selection.provider):
        # a hosted refusal falls back to the local model
        # rather than dropping the finding. Hardcoded to "ollama" rather
        # than `settings.llm_provider` — if an org points bulk itself at a
        # hosted provider, `settings.llm_provider` IS the provider that
        # just failed, so reusing it here would silently retry the exact
        # same call instead of actually falling back to something local.
        fallback_selection = ModelSelection(provider="ollama", model=deps.settings.bulk_model)
        fallback_bundle = build_bundle(
            finding,
            category,
            asset,
            evidence,
            controls_detected=controls_detected,
            change_events=change_events,
            similar_past_decisions=similar_past_decisions,
            is_new_since_last_scan=is_new_since_last_scan,
            is_hosted_call=False,
            skills=skills,
        )
        bulk_verdict, bulk_response = await _run_pass(
            deps,
            VerdictPassType.BULK,
            fallback_selection,
            system_prompt,
            fallback_bundle,
            finding_id=finding.id,
            scan_run_id=scan_run_id,
        )
        final_selection = fallback_selection
        final_bundle = fallback_bundle
        final_response = bulk_response

    if bulk_verdict is None:
        final_verdict = _synthetic_needs_human(
            raw_severity, "the model call failed or was refused and no fallback succeeded"
        )
        needs_human_forced = True
    else:
        cross = run_cross_checks(bulk_verdict, final_bundle)
        needs_human_forced = cross.forced_needs_human
        needs_human_forced |= await _verify_and_flag(
            cross.verdict,
            final_bundle,
            finding_id=finding.id,
            deps=deps,
            known_identities=known_identities,
        )
        final_verdict = cross.verdict

        if not final_verdict.requires_verification:
            wants_escalation = cross.force_escalation or needs_escalation(
                category, bulk_confidence=final_verdict.confidence, raw_severity=raw_severity
            )
            if wants_escalation:
                escalation_selection = await _model_for(
                    VerdictPassType.ESCALATION, category, deps.settings, deps.model_pin_repo
                )
                if (escalation_selection.provider, escalation_selection.model) != (
                    final_selection.provider,
                    final_selection.model,
                ):
                    escalation_bundle = build_bundle(
                        finding,
                        category,
                        asset,
                        evidence,
                        controls_detected=controls_detected,
                        change_events=change_events,
                        similar_past_decisions=similar_past_decisions,
                        is_new_since_last_scan=is_new_since_last_scan,
                        is_hosted_call=not is_local_provider(escalation_selection.provider),
                        skills=skills,
                    )
                    await check_cost_ceiling(
                        deps.llm_call_log_repo, scan_run_id, deps.settings.max_cost_usd_per_run
                    )
                    escalation_verdict, escalation_response = await _run_pass(
                        deps,
                        VerdictPassType.ESCALATION,
                        escalation_selection,
                        system_prompt,
                        escalation_bundle,
                        finding_id=finding.id,
                        scan_run_id=scan_run_id,
                    )
                    if escalation_verdict is None:
                        needs_human_forced = True
                    else:
                        esc_cross = run_cross_checks(escalation_verdict, escalation_bundle)
                        needs_human_forced = (
                            needs_human_forced
                            or esc_cross.forced_needs_human
                            or await _verify_and_flag(
                                esc_cross.verdict,
                                escalation_bundle,
                                finding_id=finding.id,
                                deps=deps,
                                known_identities=known_identities,
                            )
                        )
                        final_verdict = esc_cross.verdict
                        final_selection = escalation_selection
                        final_bundle = escalation_bundle
                        final_response = escalation_response
                        pass_type = VerdictPassType.ESCALATION

    return _RoundResult(
        verdict_schema=final_verdict,
        selection=final_selection,
        bundle=final_bundle,
        response=final_response,
        pass_type=pass_type,
        needs_human_forced=needs_human_forced,
        input_hash=input_hash,
    )


def _verification_available(deps: AdjudicationDeps) -> bool:
    return (
        deps.scope_guard is not None
        and deps.rate_limiter is not None
        and deps.evidence_repo is not None
    )


async def adjudicate_finding(
    finding: Finding,
    category: CategoryDefinition,
    asset: Asset,
    evidence: list[Evidence],
    *,
    org_name: str,
    controls_detected: list[Control],
    change_events: list[ChangeEvent],
    similar_past_decisions: list[SimilarPastDecision],
    is_new_since_last_scan: bool,
    scan_run_id: UUID,
    deps: AdjudicationDeps,
    skills: list[SelectedSkill] | None = None,
) -> AdjudicationResult:
    system_prompt = load_adjudicate_prompt(org_name=org_name)
    known_identities = {asset.value}
    working_evidence = list(evidence)
    verification_rounds_used = 0

    while True:
        round_or_cached = await _run_adjudication_round(
            finding,
            category,
            asset,
            working_evidence,
            system_prompt=system_prompt,
            known_identities=known_identities,
            controls_detected=controls_detected,
            change_events=change_events,
            similar_past_decisions=similar_past_decisions,
            is_new_since_last_scan=is_new_since_last_scan,
            scan_run_id=scan_run_id,
            deps=deps,
            skills=skills or [],
        )
        if isinstance(round_or_cached, Verdict):
            return AdjudicationResult(verdict_row=round_or_cached, from_cache=True)

        round_result = round_or_cached
        final_verdict = round_result.verdict_schema
        needs_human_forced = round_result.needs_human_forced

        if (
            final_verdict.requires_verification
            and verification_rounds_used < _MAX_VERIFICATION_ROUNDS
            and _verification_available(deps)
        ):
            verification_rounds_used += 1
            # mypy can't see through `_verification_available`'s check —
            # these three are guaranteed non-None by it.
            assert deps.scope_guard is not None
            assert deps.rate_limiter is not None
            assert deps.evidence_repo is not None
            outcomes = await execute_verifications(
                final_verdict.requires_verification,
                scan_run_id=scan_run_id,
                asset_id=asset.id,
                finding_id=finding.id,
                scope_guard=deps.scope_guard,
                rate_limiter=deps.rate_limiter,
                evidence_repo=deps.evidence_repo,
            )
            working_evidence = [*working_evidence, *(o.evidence for o in outcomes)]
            continue

        if final_verdict.requires_verification:
            # Either no verification deps configured, or the round budget
            # is spent — the model still wants more evidence than it has;
            # don't guess at an answer.
            needs_human_forced = True

        if needs_human_forced and final_verdict.verdict != "needs_human":
            final_verdict = final_verdict.model_copy(update={"verdict": "needs_human"})

        verdict_row = Verdict(
            finding_id=finding.id,
            model=round_result.selection.model,
            model_version=round_result.selection.model,
            prompt_version=ADJUDICATE_PROMPT_VERSION,
            pass_type=round_result.pass_type,
            verdict=VerdictValue(final_verdict.verdict),
            confidence=final_verdict.confidence,
            adjusted_severity=Severity(final_verdict.adjusted_severity),
            reasoning=final_verdict.reasoning,
            business_impact_hypothesis=final_verdict.business_impact_hypothesis,
            citations=final_verdict.citations,
            compensating_controls=[
                c.control
                for c in final_verdict.compensating_controls_considered
                if c.mitigates_this
            ],
            exploitability=final_verdict.exploitability.model_dump(mode="json"),
            remediation=final_verdict.remediation.model_dump(mode="json"),
            input_hash=round_result.input_hash,
            tokens_in=round_result.response.tokens_in,
            tokens_out=round_result.response.tokens_out,
            cost_usd=calculate_cost(
                round_result.selection.provider,
                round_result.response.model or round_result.selection.model,
                tokens_in=round_result.response.tokens_in,
                tokens_out=round_result.response.tokens_out,
            ),
            latency_ms=round_result.response.latency_ms,
            created_at=datetime.now(UTC),
        )
        await deps.verdict_repo.add(verdict_row)

        new_status = (
            FindingStatus.TRIAGING
            if verdict_row.verdict == VerdictValue.NEEDS_HUMAN
            else FindingStatus.TRIAGED
        )
        await deps.finding_repo.mark_status(finding.id, new_status)

        return AdjudicationResult(verdict_row=verdict_row, from_cache=False)
