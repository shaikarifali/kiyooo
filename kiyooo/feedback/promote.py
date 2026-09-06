"""feedback/promote.py — Stage 8: when N humans mark the same
category+asset a false positive for the same reason, propose a
`suppressions.yaml` entry rather than eating that noise forever. Pure —
grouping and YAML-entry construction only; opening the PR against
org-context is `feedback/github_pr.py`'s job.

Grouping is on the exact rationale string, not semantic similarity — a
human's free-text reason can't be turned into "these two mean the same
thing" without another model call, and invariant #4 forbids the model any
authority over a suppression decision. This is deliberately conservative:
it under-promotes rather than over-promotes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID

import yaml

from kiyooo.db.models import VerdictValue

if TYPE_CHECKING:
    from kiyooo.config import SuppressionsFile

_DEFAULT_MIN_COUNT = 5


@dataclass(frozen=True, slots=True)
class ReviewRecord:
    """One human review, already joined with the finding it reviewed —
    built by the caller (`kiyooo feedback promote`) from `HumanReview` +
    `Finding` + `Asset` rows, so this module stays DB-free and unit-testable.
    """

    review_id: UUID
    category_id: str
    asset_value: str
    rationale: str
    verdict: VerdictValue


@dataclass(frozen=True, slots=True)
class PromotionCandidate:
    category_id: str
    asset_values: list[str]
    reason: str
    review_ids: list[UUID]


def find_promotion_candidates(
    records: list[ReviewRecord], *, min_count: int = _DEFAULT_MIN_COUNT
) -> list[PromotionCandidate]:
    groups: dict[tuple[str, str], list[ReviewRecord]] = {}
    for record in records:
        if record.verdict != VerdictValue.FALSE_POSITIVE:
            continue
        groups.setdefault((record.category_id, record.rationale), []).append(record)

    candidates: list[PromotionCandidate] = []
    for (category_id, rationale), group in groups.items():
        if len(group) < min_count:
            continue
        asset_values = sorted({record.asset_value for record in group})
        candidates.append(
            PromotionCandidate(
                category_id=category_id,
                asset_values=asset_values,
                reason=rationale,
                review_ids=[record.review_id for record in group],
            )
        )
    return candidates


def build_suppression_entry(candidate: PromotionCandidate, *, entry_id: str) -> dict[str, object]:
    """The proposed `suppressions.yaml` entry, in the exact shape
    `config.SuppressionEntry` validates — this is what gets written into
    the PR's diff.
    """
    return {
        "id": entry_id,
        "category_id": candidate.category_id,
        "asset_values": candidate.asset_values,
        "reason": candidate.reason,
        "promoted_from_review_ids": [str(rid) for rid in candidate.review_ids],
    }


def render_updated_suppressions_yaml(
    existing: SuppressionsFile, new_entries: list[dict[str, object]]
) -> str:
    merged = existing.model_dump(mode="json")
    merged["suppressions"] = [*merged["suppressions"], *new_entries]
    return yaml.safe_dump(merged, sort_keys=False)
