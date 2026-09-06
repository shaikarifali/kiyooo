"""Closure-requires-proof: closing a ticket moves the
finding to `VERIFICATION_PENDING`, never straight to `FIXED`. This module is
the "targeted re-check" — re-runs only that finding's category predicate
against the evidence collected in a given scan_run, and flips the finding to
`FIXED` (no longer reproduces) or `REGRESSED` (still there). Scheduling this
to run automatically (daily, on ticket close) is Stage 11; this is the
decision logic itself, reusing Stage 4's own predicate evaluator so a
re-check and an original detection can never disagree about what "matches"
means.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

from kiyooo.detect.evaluate import evaluate_block, evaluate_clauses_any
from kiyooo.detect.predicates import PredicateContext

if TYPE_CHECKING:
    from datetime import datetime

    from kiyooo.config import CategoryDefinition
    from kiyooo.db.models import Asset, Evidence, Finding


class RecheckResult(enum.Enum):
    FIXED = "fixed"
    REGRESSED = "regressed"
    NO_LONGER_APPLICABLE = "no_longer_applicable"


def recheck_finding(
    finding: Finding,
    category: CategoryDefinition | None,
    asset: Asset,
    evidence: list[Evidence],
    *,
    now: datetime,
) -> RecheckResult:
    if category is None or not category.enabled:
        return RecheckResult.NO_LONGER_APPLICABLE

    ctx = PredicateContext(now=now)
    match = evaluate_block(category.detect, asset, evidence, ctx)
    if match is None:
        return RecheckResult.FIXED
    if category.suppress_if and evaluate_clauses_any(category.suppress_if, asset, evidence, ctx):
        return RecheckResult.FIXED
    return RecheckResult.REGRESSED
