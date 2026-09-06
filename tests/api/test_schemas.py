from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from kiyooo.api.schemas import (
    AssetOut,
    CoverageStatsOut,
    FindingOut,
    OwnershipOverrideRequest,
    ReviewRequest,
    VerdictOut,
)
from kiyooo.db.models import (
    AssetType,
    FindingDetector,
    FindingStatus,
    OwnerType,
    Severity,
    VerdictValue,
)

_NOW = datetime.now(UTC)


def test_asset_out_serializes_from_orm_like_object() -> None:
    class _FakeAsset:
        id = uuid.uuid4()
        type = AssetType.SUBDOMAIN
        value = "app.example.com"
        first_seen = _NOW
        last_seen = _NOW
        is_active = True
        confidence_in_scope = 0.9
        scope_reason = None
        attributes: dict[str, object] = {}

    out = AssetOut.model_validate(_FakeAsset())
    assert out.value == "app.example.com"
    assert out.type == AssetType.SUBDOMAIN

    dumped = out.model_dump(mode="json")
    assert dumped["value"] == "app.example.com"
    assert dumped["type"] == "subdomain"


def test_finding_out_from_orm_like_object() -> None:
    class _FakeFinding:
        id = uuid.uuid4()
        scan_run_id = uuid.uuid4()
        asset_id = uuid.uuid4()
        category_id = "exposed-database"
        raw_severity = Severity.CRITICAL
        title = "Database exposed"
        description = None
        detector = FindingDetector.RULE
        status = FindingStatus.NEW
        first_seen = _NOW
        last_seen = _NOW
        resolved_at = None

    out = FindingOut.model_validate(_FakeFinding())
    assert out.category_id == "exposed-database"
    assert out.status == FindingStatus.NEW


def test_verdict_out_round_trips_json_fields() -> None:
    class _FakeVerdict:
        id = uuid.uuid4()
        model = "claude-sonnet-5"
        prompt_version = "v3"
        verdict = VerdictValue.TRUE_POSITIVE
        confidence = 0.9
        adjusted_severity = Severity.HIGH
        reasoning = "clearly exposed"
        business_impact_hypothesis = "customer data at risk"
        citations = ["ev_1", "ev_2"]
        compensating_controls: list[str] = []
        exploitability = {"internet_reachable": True}
        remediation = {"summary": "close the port"}
        cost_usd = 0.01
        created_at = _NOW

    out = VerdictOut.model_validate(_FakeVerdict())
    assert out.citations == ["ev_1", "ev_2"]
    assert out.exploitability == {"internet_reachable": True}


def test_review_request_rejects_empty_rationale() -> None:
    with pytest.raises(ValidationError):
        ReviewRequest(verdict=VerdictValue.FALSE_POSITIVE, rationale="", reviewer="a@example.com")


def test_review_request_accepts_valid_payload() -> None:
    req = ReviewRequest(
        verdict=VerdictValue.FALSE_POSITIVE, rationale="confirmed FP", reviewer="a@example.com"
    )
    assert req.verdict == VerdictValue.FALSE_POSITIVE


def test_ownership_override_request_requires_owner_ref() -> None:
    with pytest.raises(ValidationError):
        OwnershipOverrideRequest(owner_type=OwnerType.USER, owner_ref="", reviewer="a@example.com")


def test_coverage_stats_out_plain_construction() -> None:
    stats = CoverageStatsOut(
        total_assets=10,
        active_assets=8,
        resolved_ownership=6,
        disputed_ownership=1,
        orphan_ownership=3,
        pct_owner_confidence_gte_0_8=0.6,
    )
    assert stats.model_dump()["pct_owner_confidence_gte_0_8"] == 0.6
