"""Bulk vs escalation model selection + per-run cost ceiling (the design
Stage 5, §2's model routing policy).

Every finding gets a bulk-pass call first — routing here only decides
whether an *escalation* pass follows it, based on what the bulk pass
actually returned: confidence below the category's
own `escalation_threshold`, severity >= high, or `category.always_escalate`.
Never a decision made in advance of seeing the bulk result.

`select_model` checks `ModelPin` first (the pinned-digest source of truth
invariant #8 wants — `kiyooo providers pin` / the web UI's Model
configuration page populate it), falling back to `Settings.bulk_model`/
`escalation_model` when no active pin exists for that role. This is the
follow-up this module's own prior version flagged as not-yet-done.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from kiyooo.db.models import ModelPinRole, Severity, VerdictPassType

if TYPE_CHECKING:
    from uuid import UUID

    from kiyooo.config import CategoryDefinition, Settings
    from kiyooo.db.repo.llm_call_log import LlmCallLogRepository
    from kiyooo.db.repo.model_pin import ModelPinRepository

_ESCALATE_SEVERITIES = frozenset({Severity.HIGH, Severity.CRITICAL})


class CostCeilingExceeded(Exception):
    """Raised before a call that would push a scan_run's total LLM spend
    past its configured ceiling. The run halts and reports rather than
    silently continuing to spend.
    """


def needs_escalation(
    category: CategoryDefinition, *, bulk_confidence: float, raw_severity: Severity
) -> bool:
    if category.always_escalate:
        return True
    if raw_severity in _ESCALATE_SEVERITIES:
        return True
    return bulk_confidence < category.escalation_threshold


@dataclass(frozen=True, slots=True)
class ModelSelection:
    provider: str
    model: str
    # Both None for "ollama"/"anthropic" via the Settings fallback (they
    # have a built-in default) — populated whenever the selection came
    # from a `ModelPin` for a bring-your-own provider, which has none.
    endpoint_url: str | None = None
    credential_ref: str | None = None


async def select_model(
    pass_type: VerdictPassType,
    settings: Settings,
    model_pin_repo: ModelPinRepository | None = None,
) -> ModelSelection:
    if model_pin_repo is not None:
        role = ModelPinRole.BULK if pass_type == VerdictPassType.BULK else ModelPinRole.ESCALATION
        pin = await model_pin_repo.get_active(role)
        if pin is not None:
            return ModelSelection(
                provider=pin.provider,
                model=pin.model,
                endpoint_url=pin.endpoint_url,
                credential_ref=pin.credential_ref,
            )
    if pass_type == VerdictPassType.BULK:
        return ModelSelection(provider=settings.llm_provider, model=settings.bulk_model)
    return ModelSelection(provider=settings.escalation_provider, model=settings.escalation_model)


async def check_cost_ceiling(
    llm_call_log_repo: LlmCallLogRepository, scan_run_id: UUID, max_cost_usd: float
) -> None:
    spent = await llm_call_log_repo.total_cost_for_scan_run(scan_run_id)
    if spent >= max_cost_usd:
        raise CostCeilingExceeded(
            f"scan_run {scan_run_id} has spent ${spent:.4f}, at or above the "
            f"${max_cost_usd:.2f} ceiling — halting further LLM calls"
        )
