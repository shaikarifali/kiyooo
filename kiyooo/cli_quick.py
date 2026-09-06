"""`kiyoo-cli` — a single-command, terminal-only front door onto the same
pipeline `kiyooo scan` / `detect` / `triage` already run, for anyone who
wants `kiyoo-cli -d example.com` instead of the web UI (`web/`) or four
separate `kiyooo` invocations.

This file imports the main tool's internals; it does not fork or reimplement
them. `kiyooo/cli.py` is untouched. Same invariants apply unchanged: passive
by default, `--active` still requires `active_scanning_enabled` + attestation
in scope.yaml, ScopeGuard still gates every packet. This is a presentation
layer, not a new pipeline.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Coroutine
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from kiyooo.cli import (
    CheckResult,
    _check_database,
    _check_llm_provider,
    _check_minio,
    _check_redis,
    _latest_scan_run_id,
    _print_authorization_banner,
    _read_seeds,
    _render_outcomes,
    _run_detect,
    _run_scan,
    _run_triage,
)
from kiyooo.config import OrgContext, OrgContextError, Settings, load_org_context
from kiyooo.db.repo.asset import AssetRepository
from kiyooo.db.repo.finding import FindingRepository
from kiyooo.db.repo.verdict import VerdictRepository
from kiyooo.db.session import make_engine, make_session_factory, session_scope
from kiyooo.logging import configure_logging
from kiyooo.recon.base import ScanProfile

app = typer.Typer(add_completion=False, help="kiyoo-cli — one-shot scan, detect, triage")
console = Console()

_SEVERITY_COLOR = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "dim",
}

_VERDICT_COLOR = {
    "true_positive": "bold red",
    "needs_human": "yellow",
    "false_positive": "green",
    "not_exploitable": "dim",
}


async def _fetch_results(
    settings: Settings, scan_run_id: uuid.UUID
) -> list[tuple[str, str, str, str | None, float | None]]:
    """(asset_value, category_id, severity, verdict, confidence) per finding.
    severity/verdict/confidence fall back to the raw finding when a finding
    has no verdict yet (e.g. --no-triage, or the cost ceiling cut triage
    short) rather than hiding the row.
    """
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    rows: list[tuple[str, str, str, str | None, float | None]] = []
    async with session_scope(session_factory) as session:
        finding_repo = FindingRepository(session)
        verdict_repo = VerdictRepository(session)
        asset_repo = AssetRepository(session)

        findings = await finding_repo.list_for_scan_run(scan_run_id)
        for finding in findings:
            asset = await asset_repo.get(finding.asset_id)
            asset_value = asset.value if asset is not None else str(finding.asset_id)
            verdicts = await verdict_repo.list_for_finding(finding.id)
            latest = verdicts[-1] if verdicts else None
            if latest is not None:
                rows.append(
                    (
                        asset_value,
                        finding.category_id,
                        latest.adjusted_severity.value,
                        latest.verdict.value,
                        latest.confidence,
                    )
                )
            else:
                rows.append(
                    (asset_value, finding.category_id, finding.raw_severity.value, None, None)
                )
    await engine.dispose()
    return rows


def _render_results(rows: list[tuple[str, str, str, str | None, float | None]]) -> None:
    if not rows:
        console.print("[dim]no findings[/dim]")
        return

    def sort_key(row: tuple[str, str, str, str | None, float | None]) -> int:
        order = ["critical", "high", "medium", "low", "info"]
        return order.index(row[2]) if row[2] in order else len(order)

    table = Table(title=f"kiyoo-cli — {len(rows)} finding(s)")
    table.add_column("target")
    table.add_column("category")
    table.add_column("severity")
    table.add_column("verdict")
    table.add_column("confidence")
    for asset_value, category_id, severity, verdict, confidence in sorted(rows, key=sort_key):
        sev_color = _SEVERITY_COLOR.get(severity, "white")
        if verdict is None:
            verdict_cell = "[dim]not triaged[/dim]"
        else:
            verdict_color = _VERDICT_COLOR.get(verdict, "white")
            verdict_cell = f"[{verdict_color}]{verdict}[/{verdict_color}]"
        table.add_row(
            asset_value,
            category_id,
            f"[{sev_color}]{severity}[/{sev_color}]",
            verdict_cell,
            f"{confidence:.2f}" if confidence is not None else "-",
        )
    console.print(table)


_PREFLIGHT_TIMEOUT_S = 3.0


async def _bounded_check(name: str, check: Coroutine[Any, Any, CheckResult]) -> str | None:
    """Wraps one `kiyooo doctor` check with a hard timeout — some
    WSL/Docker-down combinations hang on an IPv6-loopback connect attempt
    for 15s+ instead of failing fast with connection-refused, which would
    otherwise make a simple "stack isn't up" case feel like a hang.
    """
    try:
        result = await asyncio.wait_for(check, timeout=_PREFLIGHT_TIMEOUT_S)
    except TimeoutError:
        return f"{name}: no response within {_PREFLIGHT_TIMEOUT_S:.0f}s (unreachable?)"
    return None if result.ok else f"{result.name}: {result.detail}"


async def _preflight(settings: Settings, *, need_llm: bool) -> list[str]:
    """Same reachability checks `kiyooo doctor` runs, so a down stack fails
    fast with one clear message instead of the pipeline stumbling into it
    mid-run — e.g. minio's client retrying a refused connection five times
    before `_run_scan` ever surfaces an error. Returns problem
    descriptions; empty means go ahead.
    """
    named_checks = [
        ("database", _check_database(settings)),
        ("redis", _check_redis(settings)),
        ("minio", _check_minio(settings)),
    ]
    if need_llm:
        named_checks.append(("llm_provider", _check_llm_provider(settings)))
    problems = await asyncio.gather(*(_bounded_check(n, c) for n, c in named_checks))
    return [p for p in problems if p is not None]


async def _run_pipeline(
    settings: Settings,
    org_context: OrgContext,
    targets: list[str],
    profile: ScanProfile,
    *,
    active: bool,
    triage: bool,
) -> uuid.UUID | None:
    outcomes, change_events = await _run_scan(
        settings, org_context, targets, profile, active=active, dry_run=False
    )
    _render_outcomes(outcomes, dry_run=False)
    if change_events:
        console.print(f"[dim]{len(change_events)} change event(s)[/dim]")

    scan_run_id = await _latest_scan_run_id(settings)
    if scan_run_id is None:
        console.print("[yellow]no assets discovered — nothing to detect or triage[/yellow]")
        return None

    detect_outcome = await _run_detect(
        settings, org_context, scan_run_id, kev_file=None, epss_file=None, fetch_live=True
    )
    console.print(
        f"[dim]detect: {detect_outcome.created_or_updated} finding(s) created/updated[/dim]"
    )

    if triage:
        processed, counts, cost = await _run_triage(
            settings, org_context, scan_run_id, active=False
        )
        counts_str = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"
        console.print(f"[dim]triage: {processed} processed ({counts_str}), ${cost:.4f}[/dim]")

    return scan_run_id


@app.command()
def main(
    domain: list[str] = typer.Option(
        [], "-d", "--domain", help="Target domain or IP. Repeatable: -d a.com -d b.com"
    ),
    target_list: Path | None = typer.Option(
        None, "-l", "--list", help="Newline-delimited file of targets"
    ),
    profile: ScanProfile = typer.Option(
        ScanProfile.PASSIVE, "--profile", help="passive | standard | deep"
    ),
    active: bool = typer.Option(
        False,
        "--active",
        help="Enable active (packet-sending) recon stages — still requires "
        "active_scanning_enabled + attestation in scope.yaml",
    ),
    no_triage: bool = typer.Option(
        False, "--no-triage", help="Stop after detect; skip the LLM adjudication pass"
    ),
) -> None:
    """kiyoo-cli -d example.com — scan, detect, and triage in one shot,
    printed straight to the terminal. Same org-context (scope.yaml,
    categories, controls) as `kiyooo`; point KIYOOO_ORG_CONTEXT_PATH at
    yours the same way you already do for the main tool.
    """
    configure_logging()

    targets = list(domain)
    if target_list is not None:
        targets.extend(_read_seeds(target_list))
    if not targets:
        console.print("[red]give at least one -d/--domain or -l/--list[/red]")
        raise typer.Exit(code=1)

    settings = Settings()
    try:
        org_context = load_org_context(settings.org_context_path)
    except OrgContextError as exc:
        console.print(f"[red]org-context error:[/red] {exc}")
        raise typer.Exit(code=1) from None

    if active:
        if not (org_context.scope.active_scanning_enabled and org_context.scope.attestation):
            console.print(
                "[red]--active requires active_scanning_enabled: true and "
                "attestation: true in scope.yaml[/red]"
            )
            raise typer.Exit(code=1)
        _print_authorization_banner(org_context)

    problems = asyncio.run(_preflight(settings, need_llm=not no_triage))
    if problems:
        console.print("[red]stack isn't ready:[/red]")
        for problem in problems:
            console.print(f"  [red]-[/red] {problem}")
        console.print(
            "[dim]run `make dev` (and `ollama serve` if triaging), "
            "or `kiyooo doctor` for detail[/dim]"
        )
        raise typer.Exit(code=1)

    try:
        scan_run_id = asyncio.run(
            _run_pipeline(
                settings, org_context, targets, profile, active=active, triage=not no_triage
            )
        )
    except Exception as exc:  # noqa: BLE001 -- surface as a clean CLI error, not a traceback
        console.print(f"[red]kiyoo-cli failed:[/red] {exc}")
        raise typer.Exit(code=1) from None

    if scan_run_id is None:
        raise typer.Exit(code=0)

    if no_triage:
        console.print("[dim]--no-triage set: showing raw findings, no verdicts[/dim]")

    rows = asyncio.run(_fetch_results(settings, scan_run_id))
    _render_results(rows)
    console.print(f"[dim]scan_run_id: {scan_run_id}[/dim]")


if __name__ == "__main__":
    app()
