"""Compensating control detection.

Evaluates every `ControlDefinition.detect` block against one asset and
persists a `Control` row for each match — idempotently, via
`ControlRepository.upsert` (see `Control`'s docstring). This runs *before*
category evaluation, per asset, so the `Control` rows it returns can be
folded into the `PredicateContext` category evaluation uses — that's what
lets a category's `has_control` clause (in `detect` or `suppress_if`) see
this scan's controls rather than a stale set.

`requires_human_confirm_once` controls are detected and persisted like any
other — `Control` carries no "confirmed" state (no DB column for it; that's
a later-stage confirm workflow this stage doesn't build) — but
`engine.py`'s suppression resolution never auto-suppresses on one of these
alone. Suppressing on an unconfirmed control would hide a real finding from
a human entirely; that's worse than occasionally showing a human a finding
a control actually mitigates.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from kiyooo.detect.evaluate import evaluate_block

if TYPE_CHECKING:
    from kiyooo.config import ControlDefinition
    from kiyooo.db.models import Asset, Control, Evidence
    from kiyooo.db.repo.control import ControlRepository
    from kiyooo.detect.predicates import PredicateContext


async def detect_controls(
    controls: list[ControlDefinition],
    asset: Asset,
    evidence: list[Evidence],
    ctx: PredicateContext,
    control_repo: ControlRepository,
) -> list[Control]:
    now = datetime.now(UTC)
    detected: list[Control] = []
    for control in controls:
        match = evaluate_block(control.detect, asset, evidence, ctx)
        if match is None:
            continue
        evidence_id = match.evidence_ids[0] if match.evidence_ids else None
        row = await control_repo.upsert(
            asset.id,
            control.id,
            detected_by="rule",
            evidence_id=evidence_id,
            detected_at=now,
        )
        detected.append(row)
    return detected
