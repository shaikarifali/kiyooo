from __future__ import annotations

import uuid

import pytest

from kiyooo.config import CategoryDefinition, PredicateBlock, RouteConfig, Settings
from kiyooo.db.models import Severity, VerdictPassType
from kiyooo.llm.router import (
    CostCeilingExceeded,
    check_cost_ceiling,
    needs_escalation,
    select_model,
)

_SLA = {"critical": 1, "high": 7, "medium": 30, "low": 90, "info": 180}


def _category(
    *, always_escalate: bool = False, escalation_threshold: float = 0.75
) -> CategoryDefinition:
    return CategoryDefinition(
        id="test-category",
        name="Test",
        version=1,
        severity_base="medium",
        applies_to=["http_service"],
        detect=PredicateBlock(any_of=[{"internet_reachable": True}]),
        triage_hints="test",
        always_escalate=always_escalate,
        escalation_threshold=escalation_threshold,
        route=RouteConfig(assign_to="appsec", sla_days=_SLA),
    )


class _FakeLlmCallLogRepository:
    def __init__(self, spent: float) -> None:
        self._spent = spent

    async def total_cost_for_scan_run(self, scan_run_id: uuid.UUID) -> float:
        return self._spent


def test_needs_escalation_true_for_always_escalate() -> None:
    category = _category(always_escalate=True)
    assert needs_escalation(category, bulk_confidence=0.99, raw_severity=Severity.LOW) is True


def test_needs_escalation_true_for_high_severity() -> None:
    category = _category()
    assert needs_escalation(category, bulk_confidence=0.99, raw_severity=Severity.HIGH) is True
    assert needs_escalation(category, bulk_confidence=0.99, raw_severity=Severity.CRITICAL) is True


def test_needs_escalation_true_for_low_confidence() -> None:
    category = _category(escalation_threshold=0.75)
    assert needs_escalation(category, bulk_confidence=0.5, raw_severity=Severity.LOW) is True


def test_needs_escalation_false_when_none_apply() -> None:
    category = _category(escalation_threshold=0.75)
    assert needs_escalation(category, bulk_confidence=0.9, raw_severity=Severity.LOW) is False


async def test_select_model_bulk_uses_bulk_settings() -> None:
    settings = Settings(bulk_model="llama3.1:8b", llm_provider="ollama")
    selection = await select_model(VerdictPassType.BULK, settings)
    assert selection.provider == "ollama"
    assert selection.model == "llama3.1:8b"


async def test_select_model_escalation_uses_escalation_settings() -> None:
    settings = Settings(escalation_provider="anthropic", escalation_model="claude-sonnet-5")
    selection = await select_model(VerdictPassType.ESCALATION, settings)
    assert selection.provider == "anthropic"
    assert selection.model == "claude-sonnet-5"


async def test_select_model_bulk_uses_active_pin_when_present() -> None:
    """The follow-up `router.py`'s own docstring used to flag as
    not-yet-done: an active `ModelPin` for a role takes priority over
    `Settings`.
    """

    class _FakePin:
        provider = "anthropic"
        model = "claude-opus-5"
        endpoint_url = None
        credential_ref = None

    class _FakeModelPinRepo:
        async def get_active(self, role: object) -> object:
            return _FakePin()

    settings = Settings(bulk_model="llama3.1:8b", llm_provider="ollama")
    selection = await select_model(VerdictPassType.BULK, settings, _FakeModelPinRepo())  # type: ignore[arg-type]
    assert selection.provider == "anthropic"
    assert selection.model == "claude-opus-5"


async def test_select_model_falls_back_to_settings_when_no_active_pin() -> None:
    class _FakeModelPinRepo:
        async def get_active(self, role: object) -> object | None:
            return None

    settings = Settings(bulk_model="llama3.1:8b", llm_provider="ollama")
    selection = await select_model(VerdictPassType.BULK, settings, _FakeModelPinRepo())  # type: ignore[arg-type]
    assert selection.provider == "ollama"


async def test_select_model_propagates_endpoint_and_credential_ref_for_byom() -> None:
    """A bring-your-own-model pin (anything but ollama/anthropic) carries
    its own endpoint/credential through the selection — there's no
    default to fall back to for an arbitrary provider name.
    """

    class _FakePin:
        provider = "openrouter"
        model = "some/model"
        endpoint_url = "https://openrouter.ai/api/v1"
        credential_ref = "env:OPENROUTER_API_KEY"

    class _FakeModelPinRepo:
        async def get_active(self, role: object) -> object:
            return _FakePin()

    settings = Settings(bulk_model="llama3.1:8b", llm_provider="ollama")
    selection = await select_model(VerdictPassType.BULK, settings, _FakeModelPinRepo())  # type: ignore[arg-type]
    assert selection.provider == "openrouter"
    assert selection.model == "some/model"
    assert selection.endpoint_url == "https://openrouter.ai/api/v1"
    assert selection.credential_ref == "env:OPENROUTER_API_KEY"


async def test_check_cost_ceiling_passes_when_under() -> None:
    repo = _FakeLlmCallLogRepository(spent=1.0)
    await check_cost_ceiling(repo, uuid.uuid4(), max_cost_usd=5.0)  # should not raise


async def test_check_cost_ceiling_raises_when_at_or_over() -> None:
    repo = _FakeLlmCallLogRepository(spent=5.0)
    with pytest.raises(CostCeilingExceeded):
        await check_cost_ceiling(repo, uuid.uuid4(), max_cost_usd=5.0)
