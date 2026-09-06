from __future__ import annotations

import pytest
from pydantic import ValidationError

from kiyooo.triage.schema import VerdictSchema, verdict_json_schema

_VALID_PAYLOAD: dict[str, object] = {
    "verdict": "true_positive",
    "confidence": 0.9,
    "adjusted_severity": "high",
    "reasoning": "Reachable and unauthenticated [ev_1].",
    "citations": ["ev_1"],
    "exploitability": {
        "internet_reachable": True,
        "authentication_required": False,
        "preconditions": [],
        "realistic_attack_path": "Direct connection from the internet.",
    },
    "compensating_controls_considered": [],
    "business_impact_hypothesis": "Could expose customer data.",
    "remediation": {
        "summary": "Restrict to VPN.",
        "steps": ["Add firewall rule"],
        "verification": "Re-scan and confirm closed.",
        "estimated_effort": "small",
    },
    "owner_hint": {"team": "data-platform", "why": "cloud tag Owner=data-platform [ev_2]"},
    "requires_verification": [],
}


def test_valid_payload_parses() -> None:
    verdict = VerdictSchema.model_validate(_VALID_PAYLOAD)
    assert verdict.verdict == "true_positive"
    assert verdict.confidence == 0.9


def test_extra_field_rejected() -> None:
    payload = {**_VALID_PAYLOAD, "unexpected_field": "value"}
    with pytest.raises(ValidationError):
        VerdictSchema.model_validate(payload)


def test_confidence_out_of_range_rejected() -> None:
    payload = {**_VALID_PAYLOAD, "confidence": 1.5}
    with pytest.raises(ValidationError):
        VerdictSchema.model_validate(payload)


def test_invalid_verdict_value_rejected() -> None:
    payload = {**_VALID_PAYLOAD, "verdict": "maybe"}
    with pytest.raises(ValidationError):
        VerdictSchema.model_validate(payload)


def test_missing_required_field_rejected() -> None:
    payload = dict(_VALID_PAYLOAD)
    del payload["exploitability"]
    with pytest.raises(ValidationError):
        VerdictSchema.model_validate(payload)


def test_json_schema_forbids_additional_properties() -> None:
    schema = verdict_json_schema()
    assert schema["additionalProperties"] is False
    assert schema["$defs"]["Exploitability"]["additionalProperties"] is False
