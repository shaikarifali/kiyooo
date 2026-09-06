"""Ownership merge logic: "highest confidence wins; if
top two disagree and both >=0.8, mark disputed and surface to a human. Never
silently pick one."

Pure — given a list of candidates, decides the outcome. Persisting
candidates as `Ownership` rows is `enrich/ownership/__init__.py`'s job, not
this module's; keeping the decision logic free of the database is what
makes it directly unit-testable.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from kiyooo.db.models import OwnershipSource, OwnerType

_DISPUTE_THRESHOLD = 0.8


class MergeOutcome(enum.Enum):
    RESOLVED = "resolved"
    DISPUTED = "disputed"
    ORPHAN = "orphan"


@dataclass(frozen=True, slots=True)
class OwnershipCandidate:
    source: OwnershipSource
    owner_type: OwnerType
    owner_ref: str
    confidence: float
    evidence_note: str | None = None


@dataclass(frozen=True, slots=True)
class MergeResult:
    outcome: MergeOutcome
    top: OwnershipCandidate | None
    disputed_with: OwnershipCandidate | None = None


def merge(candidates: list[OwnershipCandidate]) -> MergeResult:
    if not candidates:
        return MergeResult(outcome=MergeOutcome.ORPHAN, top=None)

    ranked = sorted(candidates, key=lambda c: c.confidence, reverse=True)
    top = ranked[0]

    if len(ranked) > 1:
        second = ranked[1]
        if (
            top.confidence >= _DISPUTE_THRESHOLD
            and second.confidence >= _DISPUTE_THRESHOLD
            and top.owner_ref != second.owner_ref
        ):
            return MergeResult(outcome=MergeOutcome.DISPUTED, top=top, disputed_with=second)

    if top.confidence >= _DISPUTE_THRESHOLD:
        return MergeResult(outcome=MergeOutcome.RESOLVED, top=top)

    return MergeResult(outcome=MergeOutcome.ORPHAN, top=top)
