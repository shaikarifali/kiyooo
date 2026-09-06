from __future__ import annotations

from kiyooo.worker.schedule import SCHEDULE

_EXPECTED_TASKS = {
    "passive_discovery_scan": "hourly",
    "active_scan": "weekly",
    "refresh_kev_feed": "daily",
    "sla_escalation_sweep": "daily",
    "recheck_sweep": "daily",
}


def test_schedule_covers_every_plan_named_job() -> None:
    task_names = {entry.task_name for entry in SCHEDULE}
    assert task_names == set(_EXPECTED_TASKS)


def test_schedule_cadence_matches_plan_wording() -> None:
    for entry in SCHEDULE:
        assert entry.cadence == _EXPECTED_TASKS[entry.task_name]


def test_hourly_job_has_no_fixed_hour() -> None:
    passive = next(e for e in SCHEDULE if e.task_name == "passive_discovery_scan")
    assert passive.hour is None


def test_weekly_job_has_a_weekday() -> None:
    active = next(e for e in SCHEDULE if e.task_name == "active_scan")
    assert active.weekday is not None


def test_daily_jobs_have_a_fixed_hour() -> None:
    for name in ("refresh_kev_feed", "sla_escalation_sweep", "recheck_sweep"):
        entry = next(e for e in SCHEDULE if e.task_name == name)
        assert entry.hour is not None


def test_daily_jobs_run_at_distinct_hours_to_avoid_thundering_herd() -> None:
    daily_hours = [e.hour for e in SCHEDULE if e.cadence == "daily"]
    assert len(daily_hours) == len(set(daily_hours))
