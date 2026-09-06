"""arq worker tasks. The CLI's own `_run_*` functions
(`kiyooo/cli.py`) are the single source of truth for what each pipeline
stage does — these tasks call them on a schedule or in response to an
event trigger instead of a human typing a command. Nothing here duplicates
that logic; a bug fixed in `kiyooo scan` is fixed here too, for free.

Requires a running Redis, Postgres, and MinIO to actually execute — like
every other live-infra-touching function in this project (see
`kiyooo/ingest/adapters/*.py`'s `fetch_*` functions for the established
precedent), this is real code, not exercised by the test suite.
`tests/worker/test_schedule.py` covers the one thing here that *is* pure:
the cron schedule itself.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
from arq import cron
from arq.connections import RedisSettings

from kiyooo.cli import (
    _latest_scan_run_id,
    _run_escalate,
    _run_pipeline_chain,
    _run_recheck,
    _run_scan,
)
from kiyooo.config import OrgContext, Settings, load_org_context
from kiyooo.enrich.kev import KEV_FEED_URL
from kiyooo.recon.base import ScanProfile
from kiyooo.worker.schedule import SCHEDULE

if TYPE_CHECKING:
    from arq.cron import CronJob

_KEV_FETCH_TIMEOUT_S = 30.0


async def _run_full_pipeline_after_scan(settings: Settings, org_context: OrgContext) -> None:
    """Chains detect -> triage -> route against whatever scan just ran —
    the "deploy webhook to routed ticket" DoD is this chain, minus the
    scan step itself for the event-triggered path (`kiyooo events handle`,
    `cli.py`'s `_run_event_triggered_scan`, runs the same chain).
    """
    scan_run_id = await _latest_scan_run_id(settings)
    if scan_run_id is None:
        return
    await _run_pipeline_chain(settings, org_context, scan_run_id)


async def passive_discovery_scan(ctx: dict[str, object]) -> None:
    """Hourly — Stage 11."""
    settings = Settings()
    org_context = load_org_context(settings.org_context_path)
    seeds = [*org_context.scope.domains, *org_context.scope.wildcards]
    if not seeds:
        return
    await _run_scan(settings, org_context, seeds, ScanProfile.PASSIVE, active=False, dry_run=False)
    await _run_full_pipeline_after_scan(settings, org_context)


async def active_scan(ctx: dict[str, object]) -> None:
    """Weekly — Stage 11. Structurally cannot run unless
    scope.yaml's own authorization gates are set, same as `kiyooo scan
    --active` — this task doesn't add a second way to turn active scanning
    on, it just declines to run when the org-context gates are off.
    """
    settings = Settings()
    org_context = load_org_context(settings.org_context_path)
    if not (org_context.scope.active_scanning_enabled and org_context.scope.attestation):
        return
    seeds = [*org_context.scope.domains, *org_context.scope.wildcards]
    if not seeds:
        return
    await _run_scan(settings, org_context, seeds, ScanProfile.DEEP, active=True, dry_run=False)
    await _run_full_pipeline_after_scan(settings, org_context)


async def refresh_kev_feed(ctx: dict[str, object]) -> None:
    """Daily — Stage 11. Writes CISA's raw KEV JSON to
    `settings.kev_cache_path` so hourly passive scans read a cached file
    (`_run_detect(..., kev_file=...)`) instead of hitting the feed every
    single hour.
    """
    settings = Settings()
    async with httpx.AsyncClient() as client:
        resp = await client.get(KEV_FEED_URL, timeout=_KEV_FETCH_TIMEOUT_S)
        resp.raise_for_status()
        settings.kev_cache_path.parent.mkdir(parents=True, exist_ok=True)
        settings.kev_cache_path.write_bytes(resp.content)


async def sla_escalation_sweep(ctx: dict[str, object]) -> None:
    """Daily — the scheduled form of `kiyooo route escalate` (Stage 7)."""
    settings = Settings()
    await _run_escalate(settings)


async def recheck_sweep(ctx: dict[str, object]) -> None:
    """Daily — the scheduled form of `kiyooo route recheck` (Stage 7),
    run against the most recently completed scan's evidence.
    """
    settings = Settings()
    org_context = load_org_context(settings.org_context_path)
    scan_run_id = await _latest_scan_run_id(settings)
    if scan_run_id is None:
        return
    await _run_recheck(settings, org_context, scan_run_id)


_TASKS_BY_NAME = {
    "passive_discovery_scan": passive_discovery_scan,
    "active_scan": active_scan,
    "refresh_kev_feed": refresh_kev_feed,
    "sla_escalation_sweep": sla_escalation_sweep,
    "recheck_sweep": recheck_sweep,
}


def _build_cron_jobs() -> list[CronJob]:
    jobs: list[CronJob] = []
    for entry in SCHEDULE:
        func = _TASKS_BY_NAME[entry.task_name]
        if entry.cadence == "hourly":
            jobs.append(cron(func, minute=0))
        elif entry.cadence == "weekly":
            jobs.append(cron(func, weekday=entry.weekday, hour=entry.hour, minute=0))
        else:  # daily
            jobs.append(cron(func, hour=entry.hour, minute=0))
    return jobs


class WorkerSettings:
    """`arq.worker.run_worker` entry point — `arq kiyooo.worker.tasks.WorkerSettings`."""

    functions = list(_TASKS_BY_NAME.values())
    cron_jobs = _build_cron_jobs()
    redis_settings = RedisSettings.from_dsn(Settings().redis_url)
