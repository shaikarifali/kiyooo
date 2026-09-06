from __future__ import annotations

from kiyooo.db.models import OwnershipSource, OwnerType
from kiyooo.enrich.ownership.merge import MergeOutcome, OwnershipCandidate, merge


def _candidate(source: OwnershipSource, owner_ref: str, confidence: float) -> OwnershipCandidate:
    return OwnershipCandidate(
        source=source, owner_type=OwnerType.TEAM, owner_ref=owner_ref, confidence=confidence
    )


def test_no_candidates_is_orphan() -> None:
    result = merge([])
    assert result.outcome == MergeOutcome.ORPHAN
    assert result.top is None


def test_single_candidate_below_threshold_is_orphan_but_keeps_best_guess() -> None:
    candidate = _candidate(OwnershipSource.SIBLING_ASSET, "data-platform", 0.70)
    result = merge([candidate])
    assert result.outcome == MergeOutcome.ORPHAN
    assert result.top == candidate


def test_single_candidate_at_or_above_threshold_is_resolved() -> None:
    candidate = _candidate(OwnershipSource.MANUAL, "data-platform", 1.00)
    result = merge([candidate])
    assert result.outcome == MergeOutcome.RESOLVED
    assert result.top == candidate


def test_highest_confidence_wins_when_they_agree() -> None:
    low = _candidate(OwnershipSource.TEAM_PATTERN, "data-platform", 0.80)
    high = _candidate(OwnershipSource.CLOUD_TAG, "data-platform", 0.95)
    result = merge([low, high])
    assert result.outcome == MergeOutcome.RESOLVED
    assert result.top == high


def test_highest_confidence_wins_when_second_is_below_threshold_even_if_disagreeing() -> None:
    top = _candidate(OwnershipSource.CLOUD_TAG, "data-platform", 0.95)
    weak_disagreement = _candidate(OwnershipSource.SIBLING_ASSET, "appsec", 0.70)
    result = merge([top, weak_disagreement])
    assert result.outcome == MergeOutcome.RESOLVED
    assert result.top == top


def test_top_two_disagreeing_both_above_threshold_is_disputed() -> None:
    top = _candidate(OwnershipSource.CLOUD_TAG, "data-platform", 0.95)
    second = _candidate(OwnershipSource.CODEOWNERS, "appsec", 0.90)
    result = merge([top, second])
    assert result.outcome == MergeOutcome.DISPUTED
    assert result.top == top
    assert result.disputed_with == second


def test_top_two_agreeing_both_above_threshold_is_resolved_not_disputed() -> None:
    top = _candidate(OwnershipSource.CLOUD_TAG, "data-platform", 0.95)
    second = _candidate(OwnershipSource.CODEOWNERS, "data-platform", 0.90)
    result = merge([top, second])
    assert result.outcome == MergeOutcome.RESOLVED
    assert result.top == top


def test_dispute_never_silently_picks_a_winner() -> None:
    """The design rule verbatim: "never silently pick one." A disputed
    result still reports `top`, but the outcome tag itself is what a caller
    must check before treating it as resolved — this test exists so nobody
    "simplifies" DISPUTED handling into just reading `.top`.
    """
    top = _candidate(OwnershipSource.CLOUD_TAG, "data-platform", 0.99)
    second = _candidate(OwnershipSource.CODEOWNERS, "appsec", 0.98)
    result = merge([top, second])
    assert result.outcome != MergeOutcome.RESOLVED
