from __future__ import annotations

from datetime import timedelta

from kiyooo.metrics.health import (
    clarifying_questions_per_ticket,
    compute_health_metrics,
    cost_per_scan_run,
    findings_surfaced_per_analyst_per_week,
    median_time_to_verified_closure,
    pct_assets_with_owner_confidence_gte_0_8,
)


def test_findings_surfaced_per_analyst_per_week() -> None:
    assert findings_surfaced_per_analyst_per_week(100, analyst_count=2, weeks=5) == 10.0


def test_findings_surfaced_handles_zero_analysts_or_weeks() -> None:
    assert findings_surfaced_per_analyst_per_week(100, analyst_count=0, weeks=5) == 0.0
    assert findings_surfaced_per_analyst_per_week(100, analyst_count=2, weeks=0) == 0.0


def test_pct_assets_with_owner_confidence() -> None:
    assert pct_assets_with_owner_confidence_gte_0_8([0.9, 0.85, 0.5, 0.79]) == 0.5


def test_pct_assets_with_owner_confidence_empty_list() -> None:
    assert pct_assets_with_owner_confidence_gte_0_8([]) == 0.0


def test_clarifying_questions_per_ticket() -> None:
    assert clarifying_questions_per_ticket(clarifying_question_count=3, ticket_count=10) == 0.3


def test_clarifying_questions_per_ticket_zero_tickets() -> None:
    assert clarifying_questions_per_ticket(clarifying_question_count=3, ticket_count=0) == 0.0


def test_median_time_to_verified_closure() -> None:
    durations = [timedelta(days=1), timedelta(days=3), timedelta(days=5)]
    assert median_time_to_verified_closure(durations) == timedelta(days=3)


def test_median_time_to_verified_closure_empty_is_none() -> None:
    assert median_time_to_verified_closure([]) is None


def test_cost_per_scan_run() -> None:
    assert cost_per_scan_run(100.0, scan_run_count=4) == 25.0


def test_cost_per_scan_run_zero_runs() -> None:
    assert cost_per_scan_run(100.0, scan_run_count=0) == 0.0


def test_compute_health_metrics_bundles_everything() -> None:
    metrics = compute_health_metrics(
        finding_count=50,
        analyst_count=2,
        weeks=5,
        owner_confidences=[0.9, 0.5],
        clarifying_question_count=1,
        ticket_count=10,
        closure_durations=[timedelta(days=2)],
        decommission_candidates_retired_count=3,
        total_cost_usd=40.0,
        scan_run_count=8,
    )
    assert metrics.findings_surfaced_per_analyst_per_week == 5.0
    assert metrics.pct_assets_with_owner_confidence_gte_0_8 == 0.5
    assert metrics.clarifying_questions_per_ticket == 0.1
    assert metrics.median_time_to_verified_closure == timedelta(days=2)
    assert metrics.decommission_candidates_retired == 3
    assert metrics.cost_per_scan_run == 5.0
