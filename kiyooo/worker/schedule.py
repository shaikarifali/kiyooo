"""worker/schedule.py — Stage 11's named schedules, as plain
data. Kept separate from `worker/tasks.py` so the schedule itself (what
runs, how often) is testable without an arq/redis runtime — `tasks.py`
turns each entry into an actual `arq.cron` job at import time.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScheduleEntry:
    task_name: str
    cadence: str  # human-readable, matches the design's own wording
    hour: int | None = None  # None = every hour (only meaningful for "hourly")
    weekday: int | None = None  # 0=Monday, arq/crontab convention


# Stage 11: "continuous passive discovery (hourly), full active
# scan (weekly), KEV feed refresh (daily), SLA escalation sweep (daily)" —
# plus the re-check sweep Stage 7 built the decision logic for and Stage 11
# is explicitly responsible for scheduling.
SCHEDULE: tuple[ScheduleEntry, ...] = (
    ScheduleEntry(task_name="passive_discovery_scan", cadence="hourly", hour=None),
    ScheduleEntry(task_name="active_scan", cadence="weekly", weekday=0, hour=3),
    ScheduleEntry(task_name="refresh_kev_feed", cadence="daily", hour=2),
    ScheduleEntry(task_name="sla_escalation_sweep", cadence="daily", hour=4),
    ScheduleEntry(task_name="recheck_sweep", cadence="daily", hour=5),
)
