"""`WorkerSettings` builds cleanly at import time — no redis connection is
made by `RedisSettings.from_dsn` or `arq.cron(...)`, both are pure
construction, so this is safe to run without a live redis. The task
functions themselves make real DB/Redis/network calls and are not
exercised here — see `kiyooo/worker/tasks.py`'s module docstring.
"""

from __future__ import annotations

from kiyooo.worker.schedule import SCHEDULE
from kiyooo.worker.tasks import WorkerSettings


def test_worker_settings_has_one_function_per_scheduled_task() -> None:
    assert len(WorkerSettings.functions) == len(SCHEDULE)


def test_worker_settings_has_one_cron_job_per_schedule_entry() -> None:
    assert len(WorkerSettings.cron_jobs) == len(SCHEDULE)


def test_every_scheduled_task_name_is_a_registered_function() -> None:
    function_names = {f.__name__ for f in WorkerSettings.functions}
    assert function_names == {entry.task_name for entry in SCHEDULE}
