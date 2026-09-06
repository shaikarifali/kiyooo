from __future__ import annotations

import uuid

import yaml

from kiyooo.config import SuppressionsFile
from kiyooo.db.models import VerdictValue
from kiyooo.feedback.promote import (
    ReviewRecord,
    build_suppression_entry,
    find_promotion_candidates,
    render_updated_suppressions_yaml,
)


def _review(
    *,
    category_id: str = "exposed-database",
    asset_value: str = "10.0.0.5:3306",
    rationale: str = "internal-only via VPN",
    verdict: VerdictValue = VerdictValue.FALSE_POSITIVE,
) -> ReviewRecord:
    return ReviewRecord(
        review_id=uuid.uuid4(),
        category_id=category_id,
        asset_value=asset_value,
        rationale=rationale,
        verdict=verdict,
    )


def test_below_min_count_is_not_promoted() -> None:
    records = [_review() for _ in range(4)]
    assert find_promotion_candidates(records, min_count=5) == []


def test_at_min_count_is_promoted() -> None:
    records = [_review() for _ in range(5)]
    candidates = find_promotion_candidates(records, min_count=5)
    assert len(candidates) == 1
    assert candidates[0].category_id == "exposed-database"
    assert candidates[0].reason == "internal-only via VPN"
    assert len(candidates[0].review_ids) == 5


def test_different_rationale_does_not_merge_groups() -> None:
    records = [_review(rationale="reason A") for _ in range(5)] + [
        _review(rationale="reason B") for _ in range(5)
    ]
    candidates = find_promotion_candidates(records, min_count=5)
    assert len(candidates) == 2


def test_non_false_positive_verdicts_are_ignored() -> None:
    records = [_review(verdict=VerdictValue.TRUE_POSITIVE) for _ in range(10)]
    assert find_promotion_candidates(records, min_count=5) == []


def test_asset_values_deduplicated_and_sorted() -> None:
    records = [
        _review(asset_value="10.0.0.9:3306"),
        _review(asset_value="10.0.0.5:3306"),
        _review(asset_value="10.0.0.5:3306"),
        _review(asset_value="10.0.0.5:3306"),
        _review(asset_value="10.0.0.5:3306"),
    ]
    candidates = find_promotion_candidates(records, min_count=5)
    assert candidates[0].asset_values == ["10.0.0.5:3306", "10.0.0.9:3306"]


def test_build_suppression_entry_shape() -> None:
    records = [_review() for _ in range(5)]
    candidate = find_promotion_candidates(records, min_count=5)[0]
    entry = build_suppression_entry(candidate, entry_id="promoted-1")
    assert entry["id"] == "promoted-1"
    assert entry["category_id"] == "exposed-database"
    assert entry["reason"] == "internal-only via VPN"
    assert len(entry["promoted_from_review_ids"]) == 5  # type: ignore[arg-type]


def test_render_updated_suppressions_yaml_appends_to_existing() -> None:
    existing = SuppressionsFile.model_validate(
        {
            "suppressions": [
                {
                    "id": "existing-1",
                    "category_id": "leaked-secret",
                    "asset_values": ["repo/x"],
                    "reason": "test fixture repo",
                }
            ]
        }
    )
    new_entry = {
        "id": "promoted-1",
        "category_id": "exposed-database",
        "asset_values": ["10.0.0.5:3306"],
        "reason": "internal-only via VPN",
        "promoted_from_review_ids": [],
    }
    text = render_updated_suppressions_yaml(existing, [new_entry])
    assert "existing-1" in text
    assert "promoted-1" in text
    parsed = SuppressionsFile.model_validate(yaml.safe_load(text))
    assert len(parsed.suppressions) == 2
