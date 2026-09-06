"""Generic evaluation of a `PredicateBlock` / bare predicate-clause list
against one asset. Shared by `detect/controls.py`
(each control's own `detect:` block) and `detect/engine.py` (each
category's `detect:` and `suppress_if:` blocks) so both interpret the same
YAML shape — `all_of` is AND, `any_of` is OR, a bare clause list (like
`suppress_if`) is OR — identically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from kiyooo.detect.predicates import PREDICATES

if TYPE_CHECKING:
    from kiyooo.config import PredicateBlock, PredicateClause
    from kiyooo.db.models import Asset, Evidence
    from kiyooo.detect.predicates import PredicateContext, PredicateResult


class UnknownPredicateError(Exception):
    """A category/control YAML references a predicate name `PREDICATES`
    doesn't know about — a config bug caught at evaluation time, not a
    silent "no match." `categories lint` (CLI) checks for this ahead of
    time so it surfaces before a scan, not during one.
    """


@dataclass(frozen=True, slots=True)
class BlockMatch:
    evidence_ids: list[str] = field(default_factory=list)
    discriminator: str | None = None


def evaluate_clause(
    clause: PredicateClause, asset: Asset, evidence: list[Evidence], ctx: PredicateContext
) -> PredicateResult:
    ((name, arg),) = clause.items()
    predicate = PREDICATES.get(name)
    if predicate is None:
        raise UnknownPredicateError(f"unknown predicate {name!r}")
    return predicate(asset, evidence, ctx, arg)


def evaluate_clauses_any(
    clauses: list[PredicateClause],
    asset: Asset,
    evidence: list[Evidence],
    ctx: PredicateContext,
) -> bool:
    return any(evaluate_clause(c, asset, evidence, ctx).matched for c in clauses)


def evaluate_block(
    block: PredicateBlock, asset: Asset, evidence: list[Evidence], ctx: PredicateContext
) -> BlockMatch | None:
    all_results = [evaluate_clause(c, asset, evidence, ctx) for c in block.all_of]
    if not all(r.matched for r in all_results):
        return None

    any_results = [evaluate_clause(c, asset, evidence, ctx) for c in block.any_of]
    matched_any = [r for r in any_results if r.matched]
    if block.any_of and not matched_any:
        return None

    matched = all_results + matched_any
    evidence_ids = sorted({eid for r in matched for eid in r.evidence_ids})
    discriminator = next((r.discriminator for r in matched if r.discriminator), None)
    return BlockMatch(evidence_ids=evidence_ids, discriminator=discriminator)
