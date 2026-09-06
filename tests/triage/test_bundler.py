from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest

from kiyooo.config import CategoryDefinition, PredicateBlock, RouteConfig
from kiyooo.db.models import (
    Asset,
    AssetType,
    Evidence,
    EvidenceKind,
    Finding,
    FindingDetector,
    Severity,
)
from kiyooo.skills.loader import SelectedSkill
from kiyooo.triage.bundler import RedactionViolation, build_bundle, bundle_canonical_json

_SLA = {"critical": 1, "high": 7, "medium": 30, "low": 90, "info": 180}


def _category(**overrides: object) -> CategoryDefinition:
    defaults: dict[str, object] = dict(
        id="exposed-database",
        name="Database exposed",
        version=1,
        severity_base="critical",
        applies_to=["tcp_service"],
        detect=PredicateBlock(any_of=[{"port_in": [3306]}]),
        triage_hints="test hints",
        route=RouteConfig(assign_to="appsec", sla_days=_SLA),
    )
    defaults.update(overrides)
    return CategoryDefinition.model_validate(defaults)


def _asset(asset_type: AssetType = AssetType.TCP_SERVICE, value: str = "10.0.0.5:3306") -> Asset:
    now = datetime.now(UTC)
    return Asset(
        id=uuid.uuid4(),
        type=asset_type,
        value=value,
        first_seen=now,
        last_seen=now,
        is_active=True,
        confidence_in_scope=1.0,
        scope_reason=None,
        attributes={},
    )


def _finding(asset_id: uuid.UUID, category_id: str = "exposed-database") -> Finding:
    now = datetime.now(UTC)
    return Finding(
        id=uuid.uuid4(),
        scan_run_id=uuid.uuid4(),
        asset_id=asset_id,
        category_id=category_id,
        raw_severity=Severity.CRITICAL,
        title="Database exposed",
        description=None,
        detector=FindingDetector.RULE,
        detector_ref="exposed-database@1",
        fingerprint="fp1",
        cluster_id=uuid.uuid4(),
        first_seen=now,
        last_seen=now,
    )


def _evidence(
    kind: EvidenceKind, content: dict[str, object], *, injection_suspected: bool = False
) -> Evidence:
    return Evidence(
        id=f"ev_{uuid.uuid4().hex[:8]}",
        scan_run_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        kind=kind,
        source_tool="fixture",
        collected_at=datetime.now(UTC),
        content_ref=None,
        content_inline=content,
        content_hash="fixture",
        size_bytes=None,
        redacted=False,
        injection_suspected=injection_suspected,
    )


def _build(
    evidence: list[Evidence], *, category: CategoryDefinition | None = None, **kwargs: object
) -> dict:
    asset = _asset()
    finding = _finding(asset.id)
    return build_bundle(
        finding,
        category or _category(),
        asset,
        evidence,
        controls_detected=[],
        change_events=[],
        similar_past_decisions=[],
        is_new_since_last_scan=True,
        is_hosted_call=kwargs.pop("is_hosted_call", True),
        **kwargs,
    )


def test_bundle_has_required_top_level_keys() -> None:
    bundle = _build([_evidence(EvidenceKind.PORT_BANNER, {"port": 3306, "protocol": "tcp"})])
    assert set(bundle) >= {
        "bundle_version",
        "finding",
        "asset",
        "evidence",
        "controls_detected",
        "org_context",
        "similar_past_decisions",
        "change_context",
        "available_verification_tools",
        "skills",
    }


def test_bundle_skills_defaults_to_empty_list() -> None:
    bundle = _build([_evidence(EvidenceKind.PORT_BANNER, {"port": 3306})])
    assert bundle["skills"] == []


def test_bundle_includes_selected_skills() -> None:
    bundle = _build(
        [_evidence(EvidenceKind.PORT_BANNER, {"port": 3306})],
        skills=[SelectedSkill(name="exposed-database-playbook", body="check for auth")],
    )
    assert bundle["skills"] == [{"name": "exposed-database-playbook", "body": "check for auth"}]


def test_evidence_ids_are_stable_ev_n_within_bundle() -> None:
    evidence = [
        _evidence(EvidenceKind.PORT_BANNER, {"port": 3306}),
        _evidence(EvidenceKind.PORT_BANNER, {"port": 3307}),
    ]
    bundle = _build(evidence)
    ids = [item["id"] for item in bundle["evidence"]]
    assert ids == ["ev_1", "ev_2"]


def test_injection_suspected_flag_is_surfaced() -> None:
    evidence = [_evidence(EvidenceKind.HTTP_RESPONSE, {"body": "hi"}, injection_suspected=True)]
    bundle = _build(evidence, category=_category(applies_to=["http_service"]))
    assert bundle["evidence"][0]["injection_suspected"] is True


def test_middle_elision_shrinks_oversized_content_but_keeps_the_item() -> None:
    huge_body = "A" * 100_000
    evidence = [_evidence(EvidenceKind.HTTP_RESPONSE, {"body": huge_body})]
    bundle = _build(evidence, category=_category(applies_to=["http_service"]), token_budget=500)
    content = bundle["evidence"][0]["content"]
    assert isinstance(content, str)
    assert len(content) < len(huge_body)
    assert "elided" in content
    assert len(content) > 0  # never dropped entirely


def test_headers_only_redaction_strips_body_for_hosted_call() -> None:
    evidence = [_evidence(EvidenceKind.HTTP_RESPONSE, {"status_code": 200, "body": "secret data"})]
    category = _category(applies_to=["http_service"], redaction_profile="headers_only")
    bundle = _build(evidence, category=category, is_hosted_call=True)
    content = json.loads(bundle["evidence"][0]["content"])
    assert "body" not in content
    assert content["status_code"] == 200


def test_headers_only_redaction_does_not_apply_to_local_call() -> None:
    evidence = [_evidence(EvidenceKind.HTTP_RESPONSE, {"status_code": 200, "body": "secret data"})]
    category = _category(applies_to=["http_service"], redaction_profile="headers_only")
    bundle = _build(evidence, category=category, is_hosted_call=False)
    content = json.loads(bundle["evidence"][0]["content"])
    assert content["body"] == "secret data"


def test_local_only_category_refuses_hosted_bundle() -> None:
    evidence = [_evidence(EvidenceKind.HTTP_RESPONSE, {"body": "sk_live_secret"})]
    category = _category(applies_to=["http_service"], redaction_profile="local_only")
    with pytest.raises(RedactionViolation):
        _build(evidence, category=category, is_hosted_call=True)


def test_local_only_category_allows_local_bundle() -> None:
    evidence = [_evidence(EvidenceKind.HTTP_RESPONSE, {"body": "sk_live_secret"})]
    category = _category(applies_to=["http_service"], redaction_profile="local_only")
    bundle = _build(evidence, category=category, is_hosted_call=False)
    assert "sk_live_secret" in bundle["evidence"][0]["content"]


def test_bundle_canonical_json_is_stable_across_key_order() -> None:
    bundle_a = {"b": 1, "a": 2}
    bundle_b = {"a": 2, "b": 1}
    assert bundle_canonical_json(bundle_a) == bundle_canonical_json(bundle_b)
