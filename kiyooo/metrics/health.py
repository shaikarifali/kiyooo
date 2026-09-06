"""Product-health metrics — "track the §0.5 pain
points directly... treat a worsening trend as a release blocker, not a
dashboard curiosity." Pure functions over plain data; the CLI
(`kiyooo metrics report`) does the DB querying and hands in primitives, so
every formula here is unit-testable without a database.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from datetime import timedelta


@dataclass(frozen=True, slots=True)
class HealthMetrics:
    findings_surfaced_per_analyst_per_week: float
    pct_assets_with_owner_confidence_gte_0_8: float
    clarifying_questions_per_ticket: float
    median_time_to_verified_closure: timedelta | None
    decommission_candidates_retired: int
    cost_per_scan_run: float


def findings_surfaced_per_analyst_per_week(
    finding_count: int, *, analyst_count: int, weeks: float
) -> float:
    """the design's own warning is load-bearing: this number must not be read
    in isolation — "must not rise without true-positive yield rising."
    """
    if analyst_count <= 0 or weeks <= 0:
        return 0.0
    return finding_count / analyst_count / weeks


def pct_assets_with_owner_confidence_gte_0_8(confidences: list[float]) -> float:
    if not confidences:
        return 0.0
    return sum(1 for c in confidences if c >= 0.8) / len(confidences)


def clarifying_questions_per_ticket(*, clarifying_question_count: int, ticket_count: int) -> float:
    if ticket_count <= 0:
        return 0.0
    return clarifying_question_count / ticket_count


def median_time_to_verified_closure(closure_durations: list[timedelta]) -> timedelta | None:
    """Only findings that reached a *verified* `fixed` status count — a
    finding still sitting in `verification_pending` isn't a closure yet.
    """
    if not closure_durations:
        return None
    seconds = statistics.median(d.total_seconds() for d in closure_durations)
    return timedelta(seconds=seconds)


def cost_per_scan_run(total_cost_usd: float, *, scan_run_count: int) -> float:
    if scan_run_count <= 0:
        return 0.0
    return total_cost_usd / scan_run_count


def compute_health_metrics(
    *,
    finding_count: int,
    analyst_count: int,
    weeks: float,
    owner_confidences: list[float],
    clarifying_question_count: int,
    ticket_count: int,
    closure_durations: list[timedelta],
    decommission_candidates_retired_count: int,
    total_cost_usd: float,
    scan_run_count: int,
) -> HealthMetrics:
    return HealthMetrics(
        findings_surfaced_per_analyst_per_week=findings_surfaced_per_analyst_per_week(
            finding_count, analyst_count=analyst_count, weeks=weeks
        ),
        pct_assets_with_owner_confidence_gte_0_8=pct_assets_with_owner_confidence_gte_0_8(
            owner_confidences
        ),
        clarifying_questions_per_ticket=clarifying_questions_per_ticket(
            clarifying_question_count=clarifying_question_count, ticket_count=ticket_count
        ),
        median_time_to_verified_closure=median_time_to_verified_closure(closure_durations),
        decommission_candidates_retired=decommission_candidates_retired_count,
        cost_per_scan_run=cost_per_scan_run(total_cost_usd, scan_run_count=scan_run_count),
    )
