"""The `kiyooo` CLI. Stage 0 ships `doctor` for real; everything else is a stub
that fails loudly rather than pretending to work.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import shutil
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import typer
import yaml
from pydantic import ValidationError as PydanticValidationError
from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from kiyooo.config import OrgContext, OrgContextError, Settings, load_org_context
from kiyooo.db.models import (
    Approval,
    ApprovalStatus,
    Asset,
    AssetType,
    AuditLog,
    ChangeEvent,
    EvidenceKind,
    Exclusion,
    ExclusionSource,
    ExternalFindingRaw,
    ExternalFindingSource,
    ExternalFindingSystem,
    FindingStatus,
    HumanReview,
    ModelPin,
    ModelPinRole,
    ModuleToggle,
    Organization,
    OrgRelationship,
    ScanRun,
    ScanRunStatus,
    ScanTrigger,
    ScopeAction,
    Seed,
    SeedKind,
    Ticket,
    TicketSystem,
    VerdictValue,
)
from kiyooo.db.repo.approval import ApprovalRepository
from kiyooo.db.repo.asset import AssetRepository
from kiyooo.db.repo.asset_edge import AssetEdgeRepository
from kiyooo.db.repo.asset_snapshot import AssetSnapshotRepository
from kiyooo.db.repo.audit_log import AuditLogRepository
from kiyooo.db.repo.change_event import ChangeEventRepository
from kiyooo.db.repo.control import ControlRepository
from kiyooo.db.repo.evidence import EvidenceRepository
from kiyooo.db.repo.exclusion import ExclusionRepository
from kiyooo.db.repo.external_finding import (
    ExternalFindingRawRepository,
    ExternalFindingSourceRepository,
)
from kiyooo.db.repo.finding import FindingRepository
from kiyooo.db.repo.finding_evidence import FindingEvidenceRepository
from kiyooo.db.repo.human_review import HumanReviewRepository
from kiyooo.db.repo.identifier_verification import IdentifierVerificationRepository
from kiyooo.db.repo.llm_call_log import LlmCallLogRepository
from kiyooo.db.repo.model_pin import ModelPinRepository
from kiyooo.db.repo.module_toggle import MODULE_KEYS, ModuleToggleRepository
from kiyooo.db.repo.organization import OrganizationCreateError, OrganizationRepository
from kiyooo.db.repo.ownership import OwnershipRepository
from kiyooo.db.repo.scan_run import ScanRunRepository
from kiyooo.db.repo.seed import SeedRepository
from kiyooo.db.repo.ticket import TicketRepository
from kiyooo.db.repo.verdict import VerdictRepository
from kiyooo.db.session import make_engine, make_session_factory, session_scope
from kiyooo.detect.cases import (
    CaseAsset,
    CaseEvidence,
    build_asset,
    build_context,
    build_evidence,
    cases_path_for,
    load_cases,
)
from kiyooo.detect.engine import DetectionOutcome, run_detection
from kiyooo.detect.evaluate import UnknownPredicateError, evaluate_block
from kiyooo.detect.predicates import PREDICATES, cve_ids_from_nuclei_record
from kiyooo.diff.engine import diff_scan
from kiyooo.enrich.ai_tech import apply_ai_tech
from kiyooo.enrich.cloud_aws import CloudResourceMatch, enumerate_all
from kiyooo.enrich.epss import EpssScore, fetch_epss_scores, parse_epss_response
from kiyooo.enrich.kev import KevCatalog, fetch_kev_catalog, parse_kev_catalog
from kiyooo.enrich.ownership import OwnershipEnrichmentContext, merge_existing, resolve_ownership
from kiyooo.enrich.ownership.merge import MergeOutcome
from kiyooo.enrich.ownership.sources import (
    TerraformResource,
    build_email_to_team_map,
    parse_codeowners,
    parse_terraform_state,
)
from kiyooo.enrich.tech import apply_tech
from kiyooo.eval.corpus import LabeledCase, load_corpus, save_case
from kiyooo.eval.metrics import compute_metrics
from kiyooo.eval.runner import run_eval
from kiyooo.feedback.agreement import AgreementRecord, AgreementStats, compute_agreement
from kiyooo.feedback.github_pr import (
    GithubPrTarget,
    build_branch_name,
    build_pr_body,
    build_pr_title,
    open_pr,
)
from kiyooo.feedback.promote import (
    ReviewRecord,
    build_suppression_entry,
    find_promotion_candidates,
    render_updated_suppressions_yaml,
)
from kiyooo.graph.attack_path import AttackPath, find_attack_paths
from kiyooo.graph.builder import decay_inactive_assets, upsert_asset
from kiyooo.graph.queries import QueryError, decommission_candidates, query_assets
from kiyooo.graph.snapshot import build_snapshots
from kiyooo.ingest.adapters import mandiant as mandiant_adapter
from kiyooo.ingest.adapters import tenable as tenable_adapter
from kiyooo.ingest.adapters.generic_rest import GenericRestConfig
from kiyooo.ingest.adapters.mobile_static import MobileScanConfig
from kiyooo.ingest.adapters.prowler import ProwlerConfig
from kiyooo.ingest.adapters.trivy import TrivyConfig
from kiyooo.ingest.adapters.trufflehog import TrufflehogConfig
from kiyooo.ingest.importers.csv_generic import CsvColumnMapping, parse_csv
from kiyooo.ingest.importers.nuclei_jsonl import parse_jsonl
from kiyooo.ingest.pipeline import IngestOutcome, ingest_batch
from kiyooo.ingest.sync import (
    sync_generic_source,
    sync_mobile_static_source,
    sync_prowler_source,
    sync_trivy_source,
    sync_trufflehog_source,
)
from kiyooo.llm.connection_test import test_connection
from kiyooo.llm.credentials import resolve_credential
from kiyooo.llm.provider import LlmProvider, ProviderError
from kiyooo.llm.providers.anthropic import AnthropicProvider
from kiyooo.llm.providers.ollama import OllamaProvider
from kiyooo.llm.providers.openai_compatible import OpenAiCompatibleProvider
from kiyooo.llm.router import CostCeilingExceeded
from kiyooo.logging import configure_logging, get_logger, scan_run_context
from kiyooo.metrics import prom
from kiyooo.metrics.health import HealthMetrics, compute_health_metrics
from kiyooo.objectstore import ensure_bucket, make_minio_client
from kiyooo.recon import registry
from kiyooo.recon.base import HostRateLimiter, ReconStage, ScanProfile
from kiyooo.recon.orchestrator import (
    DEFAULT_RATE_LIMIT_RPS,
    AdapterOutcome,
    EvidenceWriter,
    Orchestrator,
)
from kiyooo.recon.scope import OrgScopeOverlay, ScopeGuard, build_org_scope_overlay
from kiyooo.route.digest import build_digest, render_digest_text
from kiyooo.route.escalation import sweep_overdue
from kiyooo.route.pipeline import RouteOutcome, route_findings
from kiyooo.route.recheck import RecheckResult, recheck_finding
from kiyooo.route.sinks.base import TicketSink
from kiyooo.route.sinks.github import GithubSink
from kiyooo.route.sinks.slack import SlackSink
from kiyooo.route.sinks.webhook import WebhookSink
from kiyooo.route.ticket_contract import dummy_context, lint_ticket_body, render_ticket_body
from kiyooo.skills.loader import SkillLoadError, load_skills, select_skills_for_category
from kiyooo.triage.agent import AdjudicationDeps, ProviderRegistry, adjudicate_finding
from kiyooo.triage.memory import embed_and_store_human_review, find_similar_past_decisions

app = typer.Typer(add_completion=False, help="kiyooo — AI-triaged Attack Surface Management")
console = Console()

# Stage 1's ToolAdapter registry owns these for real; doctor only checks PATH so a
# fresh clone tells you what's missing before you try to run a scan.
_RECON_BINARIES = ["subfinder", "httpx", "naabu", "dnsx", "tlsx"]

# "what it reads"  Stage 1 --explain requirement. Not derivable
# from the ABC (is_active only says whether it sends packets, not to what) —
# kept here, next to the README table it's meant to match, not on ToolAdapter.
_ADAPTER_READS: dict[str, str] = {
    "subfinder": "public passive-DNS / certificate-transparency sources, not the target",
    "crtsh": "crt.sh's certificate transparency log, not the target",
    "amass": "public passive-DNS / OSINT sources, not the target",
    "dnsx": "the target's DNS resolver (standard name resolution)",
    "naabu": "the target's own TCP ports (SYN/connect probe)",
    "httpx": "the target's own HTTP service (a real HTTP request)",
    "tlsx": "the target's own TLS listener (a real TLS handshake)",
    "katana": "the target's own web pages (crawls live links)",
    "nuclei": "the target's own HTTP service (dos/intrusive/fuzz-tagged templates excluded)",
    "shodan": "Shodan's own database about the target IP, not the target",
    "censys": "Censys's own database about the target IP, not the target",
}


@app.callback()
def _main() -> None:
    configure_logging()


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str
    advisory: bool = False


async def _check_database(settings: Settings) -> CheckResult:
    try:
        engine = create_async_engine(settings.database_url, pool_pre_ping=True)
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        await engine.dispose()
        return CheckResult("database", True, settings.database_url)
    except Exception as exc:
        return CheckResult("database", False, str(exc))


async def _check_redis(settings: Settings) -> CheckResult:
    try:
        import redis.asyncio as redis_asyncio

        # redis-py 5.x's `from_url` lost its type stub coverage — Stage
        # 11's arq dependency pinned redis down from 8.x, which had it.
        client = redis_asyncio.from_url(settings.redis_url)  # type: ignore[no-untyped-call]
        await client.ping()
        await client.aclose()
        return CheckResult("redis", True, settings.redis_url)
    except Exception as exc:
        return CheckResult("redis", False, str(exc))


async def _check_minio(settings: Settings) -> CheckResult:
    scheme = "https" if settings.minio_secure else "http"
    url = f"{scheme}://{settings.minio_endpoint}/minio/health/live"
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(url)
        ok = resp.status_code == 200
        return CheckResult("minio", ok, url if ok else f"{url} -> HTTP {resp.status_code}")
    except Exception as exc:
        return CheckResult("minio", False, str(exc))


async def _check_llm_provider(settings: Settings) -> CheckResult:
    url = f"{settings.llm_base_url}/api/tags"
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(url)
        ok = resp.status_code == 200
        return CheckResult("llm_provider", ok, url if ok else f"{url} -> HTTP {resp.status_code}")
    except Exception as exc:
        return CheckResult("llm_provider", False, str(exc))


async def _run_async_checks(settings: Settings) -> list[CheckResult]:
    return list(
        await asyncio.gather(
            _check_database(settings),
            _check_redis(settings),
            _check_minio(settings),
            _check_llm_provider(settings),
        )
    )


def _check_org_context(settings: Settings) -> CheckResult:
    try:
        ctx = load_org_context(settings.org_context_path)
        detail = (
            f"{settings.org_context_path}: {len(ctx.categories)} categories, "
            f"{len(ctx.teams.teams)} teams, {len(ctx.controls.controls)} controls"
        )
        return CheckResult("org_context", True, detail)
    except OrgContextError as exc:
        return CheckResult("org_context", False, str(exc))


def _check_binaries() -> list[CheckResult]:
    results = []
    for binary in _RECON_BINARIES:
        path = shutil.which(binary)
        results.append(
            CheckResult(
                f"binary:{binary}",
                path is not None,
                path or "not on PATH — needed by Stage 1 recon adapters, not Stage 0",
                advisory=True,
            )
        )
    return results


@app.command()
def doctor() -> None:
    """Check DB, redis, minio, LLM provider reachability, and org-context validity."""
    settings = Settings()
    logger = get_logger()
    logger.info("doctor.start", environment=settings.environment)

    results = asyncio.run(_run_async_checks(settings))
    results.append(_check_org_context(settings))
    results.extend(_check_binaries())

    table = Table(title="kiyooo doctor")
    table.add_column("check")
    table.add_column("status")
    table.add_column("detail")

    hard_failure = False
    for result in results:
        if result.ok:
            status = "[green]OK[/green]"
        elif result.advisory:
            status = "[yellow]WARN[/yellow]"
        else:
            status = "[red]FAIL[/red]"
            hard_failure = True
        table.add_row(result.name, status, result.detail)

    console.print(table)
    logger.info("doctor.done", hard_failure=hard_failure)
    if hard_failure:
        raise typer.Exit(code=1)


def _stub(name: str, stage: str) -> None:
    console.print(f"[yellow]{name} is not implemented yet ({stage})[/yellow]")
    raise typer.Exit(code=1)


def _classify_seed(value: str) -> AssetType:
    try:
        ipaddress.ip_address(value)
        return AssetType.IP
    except ValueError:
        return AssetType.DOMAIN


def _read_seeds(path: Path) -> list[str]:
    if not path.exists():
        raise typer.BadParameter(f"seeds file not found: {path}")
    values = [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not values:
        raise typer.BadParameter(f"{path} contains no seeds")
    return values


def _config_hash(org_context: OrgContext) -> str:
    payload = {
        "scope": org_context.scope.model_dump(mode="json"),
        "controls": org_context.controls.model_dump(mode="json"),
        "teams": org_context.teams.model_dump(mode="json"),
        "categories": {k: v.model_dump(mode="json") for k, v in org_context.categories.items()},
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


# --------------------------------------------------------------------------- #
# kiyooo-easm-standalone.md Part D §1, build item 1: org + seed model,
# exclusions. `--org` on `scan` (below) is what actually connects these to
# ScopeGuard — everything here is CRUD against the three new tables.
# --------------------------------------------------------------------------- #

org_app = typer.Typer(add_completion=False, help="Manage organizations")
app.add_typer(org_app, name="org")


@org_app.command("create")
def org_create_cmd(
    slug: str = typer.Argument(..., help="Short, URL-safe identifier, e.g. 'acme'"),
    name: str = typer.Option(..., "--name", help="Display name, e.g. 'Acme Corporation'"),
    parent: str | None = typer.Option(None, "--parent", help="Parent org's slug (a subsidiary)"),
    org_relationship: OrgRelationship = typer.Option(OrgRelationship.SELF, "--relationship"),
    legal_entity_name: str | None = typer.Option(None, "--legal-entity-name"),
    country: str | None = typer.Option(None, "--country", help="ISO 3166-1 alpha-2, e.g. 'US'"),
    active_scanning_allowed: bool = typer.Option(
        False, "--active-scanning-allowed/--no-active-scanning-allowed"
    ),
    authorization_id: str | None = typer.Option(None, "--authorization-id"),
    created_by: str = typer.Option(..., "--created-by", help="Your email"),
) -> None:
    """`--relationship third_party` forces active scanning off — refused,
    not silently corrected, if you also pass --active-scanning-allowed.
    """
    settings = Settings()

    async def _create() -> Organization:
        engine = make_engine(settings)
        session_factory = make_session_factory(engine)
        async with session_scope(session_factory) as session:
            parent_id = None
            if parent is not None:
                parent_org = await OrganizationRepository(session).get_by_slug(parent)
                if parent_org is None:
                    raise typer.BadParameter(f"no organization with slug {parent!r}")
                parent_id = parent_org.id
            return await OrganizationRepository(session).create(
                slug=slug,
                name=name,
                relationship=org_relationship,
                parent_org_id=parent_id,
                legal_entity_name=legal_entity_name,
                country=country,
                active_scanning_allowed=active_scanning_allowed,
                authorization_id=authorization_id,
                created_by=created_by,
                created_at=datetime.now(UTC),
            )

    try:
        org = asyncio.run(_create())
    except OrganizationCreateError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from None
    console.print(f"[green]created organization[/green] {org.slug} ({org.id})")


def _render_org_tree(orgs: list[Organization]) -> None:
    children: dict[uuid.UUID | None, list[Organization]] = {}
    for o in orgs:
        children.setdefault(o.parent_org_id, []).append(o)

    def add_node(parent_node: Tree, org: Organization) -> None:
        node = parent_node.add(f"{org.slug} — {org.name} ({org.relationship.value})")
        for child in children.get(org.id, []):
            add_node(node, child)

    root = Tree("organizations")
    for o in children.get(None, []):
        add_node(root, o)
    console.print(root)


@org_app.command("list")
def org_list_cmd(
    tree: bool = typer.Option(False, "--tree", help="Render as a parent/child tree"),
) -> None:
    settings = Settings()

    async def _list() -> list[Organization]:
        engine = make_engine(settings)
        session_factory = make_session_factory(engine)
        async with session_scope(session_factory) as session:
            return await OrganizationRepository(session).list_all(limit=1000)

    orgs = asyncio.run(_list())
    if not orgs:
        console.print("[dim]no organizations yet — 'kiyooo org create <slug> --name ...'[/dim]")
        return
    if tree:
        _render_org_tree(orgs)
        return

    by_id = {o.id: o for o in orgs}
    table = Table(title="organizations")
    table.add_column("slug")
    table.add_column("name")
    table.add_column("relationship")
    table.add_column("active scanning")
    table.add_column("parent")
    for o in orgs:
        table.add_row(
            o.slug,
            o.name,
            o.relationship.value,
            "yes" if o.active_scanning_allowed else "no",
            by_id[o.parent_org_id].slug if o.parent_org_id is not None else "—",
        )
    console.print(table)


def _require_exactly_one_kind_flag(
    kind_values: dict[str, str | None], kind_flags: dict[str, SeedKind], usage: str
) -> tuple[SeedKind, str]:
    """Shared by `seed add` and `exclusion add` — both take "exactly one
    of these mutually-exclusive value flags" and map the one given to a
    `SeedKind`. Factored out so the two commands' accepted kinds can't
    silently drift apart the way two separate copies of this check would
    invite.
    """
    given = [(flag, v) for flag, v in kind_values.items() if v is not None]
    if len(given) != 1:
        raise typer.BadParameter(f"pass exactly one of {usage}")
    flag, value = given[0]
    assert value is not None  # narrowed by the `given` filter above
    return kind_flags[flag], value


seed_app = typer.Typer(add_completion=False, help="Manage an organization's seeds")
app.add_typer(seed_app, name="seed")

# CLI flag name -> SeedKind. github-org/saas-tenant/brand-term are accepted
# here (a seed of every kind can be added via CLI, per the DoD) even though
# ScopeGuard can't check a target against any of them yet — see
# `SeedKind`'s docstring (db/models.py).
_SEED_KIND_FLAGS: dict[str, SeedKind] = {
    "domain": SeedKind.APEX_DOMAIN,
    "wildcard": SeedKind.WILDCARD,
    "subdomain": SeedKind.SUBDOMAIN,
    "url": SeedKind.URL,
    "ip": SeedKind.IP,
    "cidr": SeedKind.CIDR,
    "asn": SeedKind.ASN,
    "cloud_account": SeedKind.CLOUD_ACCOUNT,
    "github_org": SeedKind.GITHUB_ORG,
    "saas_tenant": SeedKind.SAAS_TENANT,
    "brand_term": SeedKind.BRAND_TERM,
    "email_domain": SeedKind.EMAIL_DOMAIN,
}


@seed_app.command("add")
def seed_add_cmd(
    org: str = typer.Option(..., "--org"),
    domain: str | None = typer.Option(None, "--domain"),
    wildcard: str | None = typer.Option(None, "--wildcard"),
    subdomain: str | None = typer.Option(None, "--subdomain"),
    url: str | None = typer.Option(None, "--url"),
    ip: str | None = typer.Option(None, "--ip"),
    cidr: str | None = typer.Option(None, "--cidr"),
    asn: str | None = typer.Option(None, "--asn"),
    cloud_account: str | None = typer.Option(None, "--cloud-account"),
    github_org: str | None = typer.Option(None, "--github-org"),
    saas_tenant: str | None = typer.Option(None, "--saas-tenant"),
    brand_term: str | None = typer.Option(None, "--brand-term"),
    email_domain: str | None = typer.Option(None, "--email-domain"),
    exclude: bool = typer.Option(
        False, "--exclude", help="This seed excludes rather than includes"
    ),
    active_scan_allowed: bool | None = typer.Option(
        None,
        "--active-scan-allowed/--no-active-scan-allowed",
        help="Per-seed override; omit to defer to the org's setting",
    ),
    note: str | None = typer.Option(None, "--note"),
    added_by: str = typer.Option(..., "--added-by", help="Your email"),
) -> None:
    kind_values: dict[str, str | None] = {
        "domain": domain,
        "wildcard": wildcard,
        "subdomain": subdomain,
        "url": url,
        "ip": ip,
        "cidr": cidr,
        "asn": asn,
        "cloud_account": cloud_account,
        "github_org": github_org,
        "saas_tenant": saas_tenant,
        "brand_term": brand_term,
        "email_domain": email_domain,
    }
    kind, value = _require_exactly_one_kind_flag(
        kind_values,
        _SEED_KIND_FLAGS,
        "--domain/--wildcard/--subdomain/--url/--ip/--cidr/--asn/--cloud-account/"
        "--github-org/--saas-tenant/--brand-term/--email-domain",
    )

    settings = Settings()

    async def _add() -> Seed:
        engine = make_engine(settings)
        session_factory = make_session_factory(engine)
        async with session_scope(session_factory) as session:
            org_row = await OrganizationRepository(session).get_by_slug(org)
            if org_row is None:
                raise typer.BadParameter(f"no organization with slug {org!r}")
            return await SeedRepository(session).create(
                org_id=org_row.id,
                kind=kind,
                value=value,
                scope_action=ScopeAction.EXCLUDE if exclude else ScopeAction.INCLUDE,
                active_scan_allowed=active_scan_allowed,
                note=note,
                added_by=added_by,
                added_at=datetime.now(UTC),
            )

    seed = asyncio.run(_add())
    console.print(
        f"[green]added seed[/green] {seed.kind.value}={seed.value} "
        f"({seed.scope_action.value}) to {org}"
    )


@seed_app.command("list")
def seed_list_cmd(org: str = typer.Option(..., "--org")) -> None:
    settings = Settings()

    async def _list() -> list[Seed]:
        engine = make_engine(settings)
        session_factory = make_session_factory(engine)
        async with session_scope(session_factory) as session:
            org_row = await OrganizationRepository(session).get_by_slug(org)
            if org_row is None:
                raise typer.BadParameter(f"no organization with slug {org!r}")
            return await SeedRepository(session).list_for_org(org_row.id)

    seeds = asyncio.run(_list())
    table = Table(title=f"seeds — {org}")
    table.add_column("id")
    table.add_column("kind")
    table.add_column("value")
    table.add_column("action")
    table.add_column("verified")
    table.add_column("active scan")
    table.add_column("added by")
    for s in seeds:
        table.add_row(
            str(s.id),
            s.kind.value,
            s.value,
            s.scope_action.value,
            "yes" if s.verified else "no",
            "org default"
            if s.active_scan_allowed is None
            else ("yes" if s.active_scan_allowed else "no"),
            s.added_by,
        )
    console.print(table)


@seed_app.command("disable")
def seed_disable_cmd(seed_id: str = typer.Argument(...)) -> None:
    settings = Settings()

    async def _disable() -> None:
        engine = make_engine(settings)
        session_factory = make_session_factory(engine)
        async with session_scope(session_factory) as session:
            await SeedRepository(session).disable(uuid.UUID(seed_id), disabled_at=datetime.now(UTC))

    asyncio.run(_disable())
    console.print(f"[green]disabled seed[/green] {seed_id}")


exclusion_app = typer.Typer(add_completion=False, help="Manage global/org exclusions")
app.add_typer(exclusion_app, name="exclusion")

# Only the kinds ScopeGuard's exclude check can act on (hostname/wildcard/
# CIDR-shaped) — matches `build_org_scope_overlay`'s own limits.
_EXCLUSION_KIND_FLAGS: dict[str, SeedKind] = {
    "domain": SeedKind.APEX_DOMAIN,
    "wildcard": SeedKind.WILDCARD,
    "cidr": SeedKind.CIDR,
    "ip": SeedKind.IP,
    "url": SeedKind.URL,
}


@exclusion_app.command("add")
def exclusion_add_cmd(
    org: str | None = typer.Option(None, "--org", help="Omit for a global default exclusion"),
    domain: str | None = typer.Option(None, "--domain"),
    wildcard: str | None = typer.Option(None, "--wildcard"),
    cidr: str | None = typer.Option(None, "--cidr"),
    ip: str | None = typer.Option(None, "--ip"),
    url: str | None = typer.Option(None, "--url"),
    reason: str = typer.Option(..., "--reason"),
    source: ExclusionSource = typer.Option(ExclusionSource.USER, "--source"),
) -> None:
    kind_values: dict[str, str | None] = {
        "domain": domain,
        "wildcard": wildcard,
        "cidr": cidr,
        "ip": ip,
        "url": url,
    }
    kind, value = _require_exactly_one_kind_flag(
        kind_values, _EXCLUSION_KIND_FLAGS, "--domain/--wildcard/--cidr/--ip/--url"
    )

    settings = Settings()

    async def _add() -> Exclusion:
        engine = make_engine(settings)
        session_factory = make_session_factory(engine)
        async with session_scope(session_factory) as session:
            org_id = None
            if org is not None:
                org_row = await OrganizationRepository(session).get_by_slug(org)
                if org_row is None:
                    raise typer.BadParameter(f"no organization with slug {org!r}")
                org_id = org_row.id
            return await ExclusionRepository(session).create(
                org_id=org_id,
                kind=kind,
                value=value,
                reason=reason,
                source=source,
                created_at=datetime.now(UTC),
            )

    excl = asyncio.run(_add())
    console.print(
        f"[green]added exclusion[/green] {excl.kind.value}={excl.value} ({org or 'global'})"
    )


@exclusion_app.command("list")
def exclusion_list_cmd(org: str | None = typer.Option(None, "--org")) -> None:
    settings = Settings()

    async def _list() -> list[Exclusion]:
        engine = make_engine(settings)
        session_factory = make_session_factory(engine)
        async with session_scope(session_factory) as session:
            if org is None:
                return await ExclusionRepository(session).list_global()
            org_row = await OrganizationRepository(session).get_by_slug(org)
            if org_row is None:
                raise typer.BadParameter(f"no organization with slug {org!r}")
            return await ExclusionRepository(session).list_for_org_and_global(org_row.id)

    exclusions = asyncio.run(_list())
    table = Table(title=f"exclusions — {org or 'global'}")
    table.add_column("kind")
    table.add_column("value")
    table.add_column("reason")
    table.add_column("source")
    table.add_column("scope")
    for e in exclusions:
        table.add_row(
            e.kind.value,
            e.value,
            e.reason,
            e.source.value,
            "global" if e.org_id is None else "org",
        )
    console.print(table)


def _print_authorization_banner(org_context: OrgContext) -> None:
    scope = org_context.scope
    console.print("[bold yellow]ACTIVE SCAN AUTHORIZED[/bold yellow]")
    console.print(f"  org: {scope.org_name}")
    console.print(f"  authorized_by: {scope.authorized_by}")
    console.print(f"  authorization_date: {scope.authorization_date}")
    console.print(f"  attestation: {scope.attestation}")


def _print_explain_table() -> None:
    import kiyooo.recon.adapters  # noqa: F401 -- registers every adapter on import

    stage_order = list(ReconStage)
    table = Table(title="kiyooo scan --explain")
    table.add_column("tool")
    table.add_column("stage")
    table.add_column("sends packets to target?")
    table.add_column("reads")
    table.add_column("rate cap (rps, per host)")
    for cls in sorted(registry.all_adapters(), key=lambda c: (stage_order.index(c.stage), c.name)):
        table.add_row(
            cls.name,
            cls.stage.value,
            "[red]yes[/red]" if cls.is_active else "[green]no[/green]",
            _ADAPTER_READS.get(cls.name, "-"),
            str(DEFAULT_RATE_LIMIT_RPS),
        )
    console.print(table)


def _render_outcomes(outcomes: list[AdapterOutcome], *, dry_run: bool) -> None:
    title = "kiyooo scan" + (" (dry-run — nothing executed)" if dry_run else "")
    table = Table(title=title)
    table.add_column("stage")
    table.add_column("tool")
    table.add_column("status")
    table.add_column("detail")
    for outcome in outcomes:
        if outcome.dry_run:
            status, detail = "[cyan]DRY-RUN[/cyan]", outcome.description or ""
        elif outcome.ok:
            status = "[green]OK[/green]"
            detail = (
                f"{outcome.evidence_count} evidence, "
                f"{outcome.allowed_targets} allowed / {outcome.denied_targets} denied"
            )
        else:
            status, detail = "[red]FAIL[/red]", outcome.error or ""
        table.add_row(outcome.stage.value, outcome.tool, status, detail)
    console.print(table)


_SEVERITY_COLOR = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "dim",
}


def _render_change_events(events: list[ChangeEvent]) -> None:
    table = Table(title="change events")
    table.add_column("kind")
    table.add_column("severity")
    table.add_column("asset_id")
    table.add_column("occurred_at")
    for event in events:
        severity = event.severity_hint.value if event.severity_hint else "info"
        color = _SEVERITY_COLOR.get(severity, "white")
        table.add_row(
            event.kind.value,
            f"[{color}]{severity}[/{color}]",
            str(event.asset_id),
            event.occurred_at.isoformat(),
        )
    console.print(table)


def _render_assets(assets: list[Asset]) -> None:
    table = Table(title=f"{len(assets)} asset(s)")
    table.add_column("type")
    table.add_column("value")
    table.add_column("is_active")
    table.add_column("first_seen")
    table.add_column("last_seen")
    for asset in assets:
        table.add_row(
            asset.type.value,
            asset.value,
            "yes" if asset.is_active else "no",
            asset.first_seen.isoformat(),
            asset.last_seen.isoformat(),
        )
    console.print(table)


providers_app = typer.Typer(
    add_completion=False, help="Which model runs bulk/escalation/embedding — local or paid"
)
app.add_typer(providers_app, name="providers")


def _default_role_settings(settings: Settings) -> dict[ModelPinRole, tuple[str, str]]:
    return {
        ModelPinRole.BULK: (settings.llm_provider, settings.bulk_model),
        ModelPinRole.ESCALATION: (settings.escalation_provider, settings.escalation_model),
        ModelPinRole.EMBEDDING: (settings.embedding_provider, settings.embedding_model),
    }


@providers_app.command("list")
def providers_list_cmd() -> None:
    """Active pin per role, falling back to `Settings` (.env) for any role
    with no pin yet — same fallback `select_model` uses at triage time.
    """
    settings = Settings()

    async def _list() -> list[ModelPin]:
        engine = make_engine(settings)
        session_factory = make_session_factory(engine)
        async with session_scope(session_factory) as session:
            return await ModelPinRepository(session).list_active()

    pins = asyncio.run(_list())
    by_role = {p.role: p for p in pins}

    table = Table(title="providers")
    table.add_column("role")
    table.add_column("provider")
    table.add_column("model")
    table.add_column("endpoint")
    table.add_column("source")
    table.add_column("pinned by")
    table.add_column("pinned at")
    for role, (default_provider, default_model) in _default_role_settings(settings).items():
        pin = by_role.get(role)
        if pin is not None:
            table.add_row(
                role.value,
                pin.provider,
                pin.model,
                pin.endpoint_url or "-",
                "pinned",
                pin.pinned_by,
                pin.pinned_at.isoformat(),
            )
        else:
            table.add_row(
                role.value, default_provider, default_model, "-", "settings (unpinned)", "-", "-"
            )
    console.print(table)


@providers_app.command("pin")
def providers_pin_cmd(
    role: ModelPinRole = typer.Option(..., "--role"),
    provider: str = typer.Option(
        ...,
        "--provider",
        help="Any name — 'ollama'/'anthropic' get this project's dedicated client; "
        "anything else (openai, openrouter, vllm, azure_openai, bedrock, a self-hosted "
        "server, ...) is bring-your-own-model, served as an OpenAI-compatible endpoint",
    ),
    model: str = typer.Option(..., "--model"),
    digest: str = typer.Option(
        ...,
        "--digest",
        help="Content/version identifier — the model name is fine for a hosted provider",
    ),
    pinned_by: str = typer.Option(..., "--pinned-by", help="Your email"),
    changelog_note: str = typer.Option(..., "--changelog-note"),
    endpoint_url: str | None = typer.Option(
        None,
        "--endpoint-url",
        help="Required for anything but ollama/anthropic — e.g. https://api.openai.com/v1",
    ),
    credential_ref: str | None = typer.Option(
        None,
        "--credential-ref",
        help="Where the API key lives — 'env:VAR_NAME' (never the key itself; invariant #6)",
    ),
    eval_run_id: str | None = typer.Option(None, "--eval-run-id"),
) -> None:
    """A pin is always a new row (invariant #8) — supersedes, never
    overwrites, whatever was previously active for this role.
    """
    if provider not in ("ollama", "anthropic") and not endpoint_url:
        raise typer.BadParameter(
            f"provider {provider!r} needs --endpoint-url — bring-your-own-model providers "
            "have no default to fall back to"
        )
    settings = Settings()

    async def _pin() -> ModelPin:
        engine = make_engine(settings)
        session_factory = make_session_factory(engine)
        async with session_scope(session_factory) as session:
            return await ModelPinRepository(session).pin(
                role=role,
                provider=provider,
                model=model,
                digest=digest,
                pinned_by=pinned_by,
                changelog_note=changelog_note,
                pinned_at=datetime.now(UTC),
                endpoint_url=endpoint_url,
                credential_ref=credential_ref,
                eval_run_id=eval_run_id,
            )

    pin = asyncio.run(_pin())
    console.print(f"[green]pinned[/green] {pin.role.value} -> {pin.provider}:{pin.model}")


@providers_app.command("test")
def providers_test_cmd(
    provider: str = typer.Option(..., "--provider"),
    model: str = typer.Option(..., "--model"),
    endpoint_url: str | None = typer.Option(
        None, "--endpoint-url", help="Required for anything but ollama/anthropic"
    ),
    credential_ref: str | None = typer.Option(
        None, "--credential-ref", help="'env:VAR_NAME' — test before you pin"
    ),
) -> None:
    """A real, zero-cost reachability check — never a real completion
    call. Ollama's /api/tags, Anthropic's GET /v1/models, or (any other
    provider name) GET {endpoint_url}/models.
    """
    settings = Settings()
    resolved_key = resolve_credential(credential_ref)
    result = asyncio.run(
        test_connection(
            provider=provider,
            model=model,
            base_url=endpoint_url or (settings.llm_base_url if provider == "ollama" else None),
            api_key=resolved_key
            or (settings.anthropic_api_key if provider == "anthropic" else None),
        )
    )
    color = "green" if result.ok else "red"
    status = "OK" if result.ok else "FAILED"
    console.print(f"[{color}]{status}[/{color}] ({result.latency_ms}ms) {result.detail}")
    if not result.ok:
        raise typer.Exit(code=1)


async def _resolve_org_scope(
    session: AsyncSession, org_slug: str | None
) -> tuple[OrgScopeOverlay | None, bool | None]:
    """Shared by every command that builds a `ScopeGuard` and accepts
    `--org` (`_run_scan`, `_run_triage`) — one place computing the overlay
    and the org's `active_scanning_allowed` flag together, so they can
    never be threaded through separately and drift out of sync with each
    other (which is exactly how the org-level active-scan gate got left
    unenforced the first time: the overlay existed, the flag wasn't wired
    alongside it).
    """
    if org_slug is None:
        return None, None
    org_row = await OrganizationRepository(session).get_by_slug(org_slug)
    if org_row is None:
        raise ValueError(
            f"no organization with slug {org_slug!r} — create it first with 'kiyooo org create'"
        )
    org_seeds = await SeedRepository(session).list_for_org(org_row.id)
    org_exclusions = await ExclusionRepository(session).list_for_org_and_global(org_row.id)
    overlay = build_org_scope_overlay(org_seeds, org_exclusions)
    return overlay, org_row.active_scanning_allowed


async def _run_scan(
    settings: Settings,
    org_context: OrgContext,
    seed_values: list[str],
    profile: ScanProfile,
    *,
    active: bool,
    dry_run: bool,
    org_slug: str | None = None,
) -> tuple[list[AdapterOutcome], list[ChangeEvent]]:
    """One scan is one Postgres transaction: everything this run writes commits
    together when `session_scope` exits, or nothing does if an unhandled bug
    escapes the orchestrator's own per-adapter error handling. Stage 1 accepts
    that tradeoff for simplicity; a crash mid-run loses the run rather than
    partially persisting it. Revisit if a later stage's scheduler needs
    resumable, incrementally-visible progress.

    After recon completes, Stage 2 takes over in the same transaction: decay
    assets unseen for too long, snapshot every asset this scan touched, then
    diff against the previous completed scan's snapshots. `--dry-run` skips
    all of it — there's no scan to snapshot or diff.
    """
    logger = get_logger()
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)

    minio_client = make_minio_client(settings)
    if not dry_run:
        await asyncio.to_thread(ensure_bucket, minio_client, settings.minio_bucket)

    scan_run_id = uuid.uuid4()
    change_events: list[ChangeEvent] = []
    with scan_run_context(scan_run_id):
        async with session_scope(session_factory) as session:
            scan_run_repo = ScanRunRepository(session)
            asset_repo = AssetRepository(session)
            asset_edge_repo = AssetEdgeRepository(session)
            asset_snapshot_repo = AssetSnapshotRepository(session)
            evidence_repo = EvidenceRepository(session)
            audit_log_repo = AuditLogRepository(session)
            change_event_repo = ChangeEventRepository(session)

            # Resolve "the previous scan" before this run's own row can be
            # returned by recent_completed() — it isn't COMPLETED yet.
            previous_run = next(iter(await scan_run_repo.recent_completed(1)), None)
            previous_scan_run_id = previous_run.id if previous_run is not None else None

            await scan_run_repo.add(
                ScanRun(
                    id=scan_run_id,
                    started_at=datetime.now(UTC),
                    finished_at=None,
                    status=ScanRunStatus.PENDING,
                    scope_hash=hashlib.sha256(
                        json.dumps(
                            org_context.scope.model_dump(mode="json"), sort_keys=True
                        ).encode()
                    ).hexdigest(),
                    config_hash=_config_hash(org_context),
                    trigger=ScanTrigger.MANUAL,
                )
            )

            seed_assets: list[Asset] = [
                await upsert_asset(asset_repo, _classify_seed(v), v, confidence_in_scope=1.0)
                for v in seed_values
            ]

            org_overlay, org_active_scanning_allowed = await _resolve_org_scope(session, org_slug)

            scope_guard = ScopeGuard(
                org_context.scope,
                cli_active_flag=active,
                audit_log_repo=audit_log_repo,
                scan_run_id=scan_run_id,
                org_overlay=org_overlay,
                org_active_scanning_allowed=org_active_scanning_allowed,
            )
            evidence_writer = EvidenceWriter(
                evidence_repo=evidence_repo,
                asset_repo=asset_repo,
                asset_edge_repo=asset_edge_repo,
                minio_client=minio_client,
                bucket=settings.minio_bucket,
                scan_run_id=scan_run_id,
            )
            orchestrator = Orchestrator(
                scan_run_repo=scan_run_repo,
                evidence_writer=evidence_writer,
                scope_guard=scope_guard,
                profile=profile,
                dry_run=dry_run,
                logger=logger,
            )
            outcomes = await orchestrator.run(seed_assets, scan_run_id)

            if not dry_run:
                await decay_inactive_assets(asset_repo, scan_run_repo)

                touched_asset_ids = {
                    evidence.asset_id for evidence in await evidence_repo.for_scan_run(scan_run_id)
                }
                touched_asset_ids.update(a.id for a in seed_assets)
                resolved_assets = [await asset_repo.get(aid) for aid in touched_asset_ids]
                touched_assets = [asset for asset in resolved_assets if asset is not None]

                await build_snapshots(
                    asset_snapshot_repo,
                    evidence_repo,
                    scan_run_id=scan_run_id,
                    assets=touched_assets,
                )
                change_events = await diff_scan(
                    asset_repo,
                    asset_snapshot_repo,
                    change_event_repo,
                    scan_run_id=scan_run_id,
                    previous_scan_run_id=previous_scan_run_id,
                    assets=touched_assets,
                )

    await engine.dispose()
    return outcomes, change_events


@app.command()
def scan(
    seeds: Path | None = typer.Option(
        None, "--seeds", help="Path to a newline-delimited seed file (required unless --explain)"
    ),
    profile: ScanProfile = typer.Option(
        ScanProfile.PASSIVE, "--profile", help="passive | standard | deep"
    ),
    active: bool = typer.Option(False, "--active", help="Enable active (packet-sending) stages"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print what would run; execute and touch nothing"
    ),
    explain: bool = typer.Option(
        False, "--explain", help="Print the tool/stage/network table and exit"
    ),
    org: str | None = typer.Option(
        None,
        "--org",
        help="Merge this organization's DB-backed seeds/exclusions into ScopeGuard "
        "alongside scope.yaml (kiyooo-easm-standalone.md Part D §1). Omit for "
        "scope.yaml-only behavior, unchanged.",
    ),
) -> None:
    """Run a recon scan. Passive by default. --active requires
    active_scanning_enabled and attestation in scope.yaml. --dry-run touches
    nothing. --explain documents every adapter without running anything.
    """
    if explain:
        _print_explain_table()
        return
    if seeds is None:
        raise typer.BadParameter("--seeds is required unless --explain is given")

    settings = Settings()
    try:
        org_context = load_org_context(settings.org_context_path)
    except OrgContextError as exc:
        console.print(f"[red]org-context error:[/red] {exc}")
        raise typer.Exit(code=1) from None

    if active and not dry_run:
        if not (org_context.scope.active_scanning_enabled and org_context.scope.attestation):
            console.print(
                "[red]--active requires active_scanning_enabled: true and "
                "attestation: true in scope.yaml[/red]"
            )
            raise typer.Exit(code=1)
        _print_authorization_banner(org_context)

    seed_values = _read_seeds(seeds)
    started = time.monotonic()
    try:
        outcomes, change_events = asyncio.run(
            _run_scan(
                settings,
                org_context,
                seed_values,
                profile,
                active=active,
                dry_run=dry_run,
                org_slug=org,
            )
        )
    except Exception as exc:  # noqa: BLE001 -- surface as a clean CLI error, not a traceback
        console.print(f"[red]scan failed:[/red] {exc}")
        raise typer.Exit(code=1) from None

    prom.scan_duration_seconds.observe(time.monotonic() - started)
    prom.assets_discovered_total.inc(sum(len(o.discovered_assets) for o in outcomes))
    for outcome in outcomes:
        if not outcome.ok:
            prom.tool_failures_total.labels(tool=outcome.tool).inc()
    if settings.metrics_textfile_path is not None:
        prom.write_textfile(settings.metrics_textfile_path)

    _render_outcomes(outcomes, dry_run=dry_run)
    if change_events:
        _render_change_events(change_events)
    if any(not o.ok for o in outcomes):
        raise typer.Exit(code=1)


def _build_provider(
    provider_name: str, *, endpoint_url: str | None, credential_ref: str | None, settings: Settings
) -> LlmProvider:
    """ "ollama"/"anthropic" get the dedicated client this project ships
    for each; any other provider name (openai, openrouter, vllm,
    azure_openai, bedrock, a self-hosted server, anything) is bring-your-
    own-model — served by `OpenAiCompatibleProvider` against
    `endpoint_url`, which is required for those since there's no sensible
    default to guess for an arbitrary provider.
    """
    if provider_name == "ollama":
        return OllamaProvider(base_url=endpoint_url or settings.llm_base_url)
    if provider_name == "anthropic":
        api_key = resolve_credential(credential_ref) or settings.anthropic_api_key
        if not api_key:
            raise ProviderError(
                "anthropic needs an API key — set ANTHROPIC_API_KEY or pin a credential_ref"
            )
        return AnthropicProvider(api_key)
    if not endpoint_url:
        raise ProviderError(
            f"provider {provider_name!r} needs an endpoint_url — bring-your-own-model providers "
            "have no default to fall back to (pin one with --endpoint-url)"
        )
    return OpenAiCompatibleProvider(
        base_url=endpoint_url, api_key=resolve_credential(credential_ref)
    )


async def _build_provider_registry(
    settings: Settings, model_pin_repo: ModelPinRepository
) -> ProviderRegistry:
    """Base registry — ollama always, anthropic if a key's configured,
    exactly as before this existed — plus one entry per bring-your-own
    provider any *active* pin (any role) actually references, built from
    that pin's own `endpoint_url`/`credential_ref`. `select_model`/the
    active pins decide *which* model runs each role; this only decides
    *how to reach* whatever they pick.
    """
    providers: dict[str, LlmProvider] = {"ollama": OllamaProvider(base_url=settings.llm_base_url)}
    if settings.anthropic_api_key:
        providers["anthropic"] = AnthropicProvider(settings.anthropic_api_key)
    for pin in await model_pin_repo.list_active():
        if pin.provider in providers:
            continue
        providers[pin.provider] = _build_provider(
            pin.provider,
            endpoint_url=pin.endpoint_url,
            credential_ref=pin.credential_ref,
            settings=settings,
        )
    return ProviderRegistry(providers)


async def _run_triage(
    settings: Settings,
    org_context: OrgContext,
    scan_run_id: uuid.UUID,
    *,
    active: bool,
    org_slug: str | None = None,
) -> tuple[int, dict[str, int], float]:
    """Returns (findings processed, counts by verdict value, total cost USD)."""
    logger = get_logger()
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)

    skills = load_skills(settings.org_context_path / "skills")

    counts: dict[str, int] = {}
    total_cost = 0.0
    processed = 0

    async with session_scope(session_factory) as session:
        finding_repo = FindingRepository(session)
        evidence_repo = EvidenceRepository(session)
        finding_evidence_repo = FindingEvidenceRepository(session)
        asset_repo = AssetRepository(session)
        control_repo = ControlRepository(session)
        change_event_repo = ChangeEventRepository(session)
        human_review_repo = HumanReviewRepository(session)
        verdict_repo = VerdictRepository(session)
        llm_call_log_repo = LlmCallLogRepository(session)
        identifier_verification_repo = IdentifierVerificationRepository(session)
        audit_log_repo = AuditLogRepository(session)
        model_pin_repo = ModelPinRepository(session)

        # Built from whatever's actually pinned (any provider, not just
        # ollama/anthropic) — see `_build_provider_registry`.
        provider_registry = await _build_provider_registry(settings, model_pin_repo)

        async def embed(text: str) -> list[float]:
            role_pin = await model_pin_repo.get_active(ModelPinRole.EMBEDDING)
            provider_name = role_pin.provider if role_pin else settings.embedding_provider
            model_name = role_pin.model if role_pin else settings.embedding_model
            provider = provider_registry.get(provider_name)
            vectors = await provider.embed([text], model=model_name)
            return vectors[0]

        # Stage 6: verification tools send real packets, so they go through
        # the exact same ScopeGuard every Stage 1 active adapter does —
        # `--active` alone doesn't bypass it, it only sets the CLI half of
        # ScopeGuard's own three-part authorization check (scope.yaml's
        # active_scanning_enabled + attestation are the other two). `--org`
        # is threaded through the same way `scan` does: a finding whose
        # asset only exists because of an org seed (not scope.yaml) would
        # otherwise fail every Stage 6 verification with a DENY once
        # ScopeGuard here had no matching domain/wildcard/cidr to check it
        # against — same org, same overlay, or verification for that
        # finding silently breaks.
        org_overlay, org_active_scanning_allowed = await _resolve_org_scope(session, org_slug)
        scope_guard = ScopeGuard(
            org_context.scope,
            cli_active_flag=active,
            audit_log_repo=audit_log_repo,
            scan_run_id=scan_run_id,
            org_overlay=org_overlay,
            org_active_scanning_allowed=org_active_scanning_allowed,
        )
        rate_limiter = HostRateLimiter(DEFAULT_RATE_LIMIT_RPS)

        deps = AdjudicationDeps(
            settings=settings,
            providers=provider_registry,
            verdict_repo=verdict_repo,
            llm_call_log_repo=llm_call_log_repo,
            identifier_verification_repo=identifier_verification_repo,
            finding_repo=finding_repo,
            scope_guard=scope_guard,
            rate_limiter=rate_limiter,
            evidence_repo=evidence_repo,
            model_pin_repo=model_pin_repo,
        )

        findings = [
            f
            for f in await finding_repo.list_for_scan_run(scan_run_id)
            if f.status == FindingStatus.NEW
        ]

        for finding in findings:
            category = org_context.categories.get(finding.category_id)
            if category is None:
                logger.warning("triage.unknown_category", category_id=finding.category_id)
                continue
            asset = await asset_repo.get(finding.asset_id)
            if asset is None:
                continue

            links = await finding_evidence_repo.list_for_finding(finding.id)
            evidence_items = []
            for link in links:
                item = await evidence_repo.get(link.evidence_id)
                if item is not None:
                    evidence_items.append(item)

            controls_detected = await control_repo.list_for_asset(asset.id)
            change_events = await change_event_repo.for_asset(asset.id)
            is_new = finding.first_seen == finding.last_seen

            try:
                similar = await find_similar_past_decisions(
                    finding.title,
                    finding.category_id,
                    human_review_repo=human_review_repo,
                    embed=embed,
                )
            except Exception as exc:  # noqa: BLE001 -- memory being unavailable isn't fatal
                logger.warning("triage.memory_unavailable", error=str(exc))
                similar = []

            try:
                result = await adjudicate_finding(
                    finding,
                    category,
                    asset,
                    evidence_items,
                    org_name=org_context.scope.org_name,
                    controls_detected=controls_detected,
                    change_events=change_events,
                    similar_past_decisions=similar,
                    is_new_since_last_scan=is_new,
                    scan_run_id=scan_run_id,
                    deps=deps,
                    skills=select_skills_for_category(skills, category),
                )
            except CostCeilingExceeded as exc:
                logger.warning("triage.cost_ceiling_exceeded", error=str(exc))
                break
            except ProviderError as exc:
                logger.warning("triage.provider_error", finding_id=str(finding.id), error=str(exc))
                continue

            processed += 1
            verdict_value = result.verdict_row.verdict.value
            counts[verdict_value] = counts.get(verdict_value, 0) + 1
            total_cost += float(result.verdict_row.cost_usd)
            prom.findings_by_verdict_total.labels(verdict=verdict_value).inc()
            if result.from_cache:
                prom.cache_hits_total.inc()
            else:
                prom.cache_misses_total.inc()

    prom.llm_cost_usd.observe(total_cost)
    if settings.metrics_textfile_path is not None:
        prom.write_textfile(settings.metrics_textfile_path)

    await engine.dispose()
    return processed, counts, total_cost


@app.command()
def triage(
    scan_run: str = typer.Option(
        ..., "--scan-run", help="scan_run UUID to triage NEW findings from"
    ),
    active: bool = typer.Option(
        False,
        "--active",
        help="Allow Stage 6 verification tools to send real packets (requires "
        "active_scanning_enabled and attestation in scope.yaml)",
    ),
    org: str | None = typer.Option(
        None,
        "--org",
        help="Same org whose seeds/exclusions the originating `scan --org` used — "
        "needed so Stage 6 verification of an org-only-seeded finding isn't "
        "denied for a target scope.yaml alone wouldn't recognize.",
    ),
) -> None:
    """Adjudicate every NEW finding from --scan-run: bulk model call,
    validator cross-checks + identifier verification, escalation when
    warranted, cached on identical rescan. Without
    --active, a verdict that requests verification stays needs_human —
    every requires_verification tool call is an active probe.
    """
    try:
        scan_run_id = uuid.UUID(scan_run)
    except ValueError:
        raise typer.BadParameter(f"--scan-run must be a UUID, got {scan_run!r}") from None

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

    try:
        processed, counts, total_cost = asyncio.run(
            _run_triage(settings, org_context, scan_run_id, active=active, org_slug=org)
        )
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from None

    table = Table(title="kiyooo triage")
    table.add_column("metric")
    table.add_column("value")
    table.add_row("findings processed", str(processed))
    for verdict_value, count in counts.items():
        table.add_row(f"verdict: {verdict_value}", str(count))
    table.add_row("total cost (USD)", f"${total_cost:.4f}")
    console.print(table)


async def _run_review(
    settings: Settings,
    finding_id: uuid.UUID,
    *,
    verdict: VerdictValue,
    rationale: str,
    reviewer: str,
) -> HumanReview:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)

    async with session_scope(session_factory) as session:
        finding_repo = FindingRepository(session)
        asset_repo = AssetRepository(session)
        evidence_repo = EvidenceRepository(session)
        finding_evidence_repo = FindingEvidenceRepository(session)
        verdict_repo = VerdictRepository(session)
        human_review_repo = HumanReviewRepository(session)
        model_pin_repo = ModelPinRepository(session)

        provider_registry = await _build_provider_registry(settings, model_pin_repo)

        async def embed(text: str) -> list[float]:
            role_pin = await model_pin_repo.get_active(ModelPinRole.EMBEDDING)
            provider_name = role_pin.provider if role_pin else settings.embedding_provider
            model_name = role_pin.model if role_pin else settings.embedding_model
            provider = provider_registry.get(provider_name)
            vectors = await provider.embed([text], model=model_name)
            return vectors[0]

        finding = await finding_repo.get(finding_id)
        if finding is None:
            raise ValueError(f"finding {finding_id} not found")
        asset = await asset_repo.get(finding.asset_id)
        if asset is None:
            raise ValueError(f"finding {finding_id} has no asset")

        past_verdicts = await verdict_repo.list_for_finding(finding_id)
        agreed = bool(past_verdicts) and past_verdicts[-1].verdict == verdict

        review = HumanReview(
            id=uuid.uuid4(),
            finding_id=finding_id,
            reviewer=reviewer,
            agreed_with_model=agreed,
            final_verdict=verdict,
            rationale=rationale,
            created_at=datetime.now(UTC),
        )
        await human_review_repo.add(review)

        try:
            await embed_and_store_human_review(
                review.id,
                f"{verdict.value}: {rationale}",
                human_review_repo=human_review_repo,
                embed=embed,
            )
        except Exception as exc:  # noqa: BLE001 -- embedding being unavailable isn't fatal
            get_logger().warning("review.embedding_unavailable", error=str(exc))

        links = await finding_evidence_repo.list_for_finding(finding_id)
        evidence_items = []
        for link in links:
            item = await evidence_repo.get(link.evidence_id)
            if item is not None:
                evidence_items.append(item)

        case = LabeledCase(
            id=f"human-review-{review.id}",
            category_id=finding.category_id,
            asset=CaseAsset(type=asset.type, value=asset.value),
            evidence=[
                CaseEvidence(kind=item.kind, content=item.content_inline or {})
                for item in evidence_items
            ],
            human_verdict=verdict.value,
            human_severity=finding.raw_severity.value,
            notes=rationale,
        )
        save_case(case, settings.eval_corpus_path)

    await engine.dispose()
    return review


@app.command()
def review(
    finding_id: str = typer.Argument(...),
    verdict: str = typer.Option(
        ..., "--verdict", help="true_positive | false_positive | not_exploitable | needs_human"
    ),
    rationale: str = typer.Option(..., "--rationale"),
    reviewer: str = typer.Option(..., "--reviewer", help="Email of the human reviewing this"),
) -> None:
    """Records a human verdict on a finding: writes a
    `human_review` row that feeds Stage 5's similar-past-decisions memory,
    embeds it for future retrieval, and auto-adds the finding to the local
    eval corpus so labeled data compounds every time someone reviews
    something. Run `kiyooo feedback promote` periodically to turn a
    repeated false-positive rationale into a proposed suppression.
    """
    try:
        verdict_value = VerdictValue(verdict)
    except ValueError:
        raise typer.BadParameter(
            f"--verdict must be one of {[v.value for v in VerdictValue]}, got {verdict!r}"
        ) from None

    settings = Settings()
    try:
        review_row = asyncio.run(
            _run_review(
                settings,
                uuid.UUID(finding_id),
                verdict=verdict_value,
                rationale=rationale,
                reviewer=reviewer,
            )
        )
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from None

    agreement = "agreed" if review_row.agreed_with_model else "disagreed"
    console.print(f"[green]recorded[/green] — {agreement} with the model's verdict")


async def _run_agreement(settings: Settings) -> dict[tuple[str, str, str], AgreementStats]:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        human_review_repo = HumanReviewRepository(session)
        finding_repo = FindingRepository(session)
        verdict_repo = VerdictRepository(session)

        reviews = await human_review_repo.list_all_reviews()
        records: list[AgreementRecord] = []
        for review_row in reviews:
            finding = await finding_repo.get(review_row.finding_id)
            if finding is None:
                continue
            verdicts = await verdict_repo.list_for_finding(review_row.finding_id)
            if not verdicts:
                continue
            latest = verdicts[-1]
            records.append(
                AgreementRecord(
                    category_id=finding.category_id,
                    model=latest.model,
                    prompt_version=latest.prompt_version,
                    agreed=review_row.agreed_with_model,
                )
            )
    await engine.dispose()
    return compute_agreement(records)


async def _sweep_promotions(
    settings: Settings, org_context: OrgContext, *, min_count: int, dry_run: bool
) -> list[str]:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    prs: list[str] = []

    async with session_scope(session_factory) as session:
        human_review_repo = HumanReviewRepository(session)
        finding_repo = FindingRepository(session)
        asset_repo = AssetRepository(session)

        reviews = await human_review_repo.list_unpromoted()
        records: list[ReviewRecord] = []
        for review_row in reviews:
            finding = await finding_repo.get(review_row.finding_id)
            if finding is None:
                continue
            asset = await asset_repo.get(finding.asset_id)
            if asset is None:
                continue
            records.append(
                ReviewRecord(
                    review_id=review_row.id,
                    category_id=finding.category_id,
                    asset_value=asset.value,
                    rationale=review_row.rationale,
                    verdict=review_row.final_verdict,
                )
            )

        candidates = find_promotion_candidates(records, min_count=min_count)
        if not candidates:
            await engine.dispose()
            return prs

        if dry_run or not (settings.org_context_repo and settings.github_token):
            for candidate in candidates:
                prs.append(
                    f"[dry-run] would propose suppression for {candidate.category_id} "
                    f"covering {len(candidate.asset_values)} asset(s): {candidate.reason!r}"
                )
            await engine.dispose()
            return prs

        target = GithubPrTarget(repo=settings.org_context_repo, token=settings.github_token)
        async with httpx.AsyncClient() as client:
            for candidate in candidates:
                entry_id = f"promoted-{candidate.category_id}-{uuid.uuid4().hex[:8]}"
                entry = build_suppression_entry(candidate, entry_id=entry_id)
                content = render_updated_suppressions_yaml(org_context.suppressions, [entry])
                branch = build_branch_name(candidate, suffix=uuid.uuid4().hex[:6])
                pr_url = await open_pr(
                    client,
                    target,
                    branch_name=branch,
                    new_file_content=content,
                    pr_title=build_pr_title(candidate),
                    pr_body=build_pr_body(candidate),
                )
                await human_review_repo.mark_promoted(candidate.review_ids)
                prs.append(pr_url)

    await engine.dispose()
    return prs


feedback_app = typer.Typer(add_completion=False, help="Human-feedback loop: agreement + promotion")
app.add_typer(feedback_app, name="feedback")


@feedback_app.command(name="agreement")
def feedback_agreement_cmd() -> None:
    """Model/human agreement rate per (category, model, prompt_version).
    Low-agreement categories are the ones whose triage_hints need
    rewriting — see Stage 8.
    """
    settings = Settings()
    stats = asyncio.run(_run_agreement(settings))
    table = Table(title="kiyooo feedback agreement")
    table.add_column("category")
    table.add_column("model")
    table.add_column("prompt_version")
    table.add_column("agreement rate")
    table.add_column("n")
    for (category_id, model, prompt_version), stat in sorted(stats.items()):
        table.add_row(category_id, model, prompt_version, f"{stat.rate:.0%}", str(stat.total))
    console.print(table)


@feedback_app.command(name="promote")
def feedback_promote_cmd(
    min_count: int = typer.Option(
        5, "--min-count", help="Human reviews needed before a rationale gets promoted"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print candidates without opening a PR"),
) -> None:
    """Sweeps unpromoted human reviews: N false-positive reviews sharing
    the same category+rationale become a proposed `suppressions.yaml`
    entry, opened as a PR against org_context_repo for a human to merge.
    Without org_context_repo/github_token configured (or with --dry-run),
    prints what would be proposed instead of opening anything — nothing is
    ever suppressed automatically. See Stage 8.
    """
    settings = Settings()
    try:
        org_context = load_org_context(settings.org_context_path)
    except OrgContextError as exc:
        console.print(f"[red]org-context error:[/red] {exc}")
        raise typer.Exit(code=1) from None

    results = asyncio.run(
        _sweep_promotions(settings, org_context, min_count=min_count, dry_run=dry_run)
    )
    if not results:
        console.print("[green]no promotion candidates[/green]")
        return
    for line in results:
        console.print(line)


def _build_sinks(settings: Settings) -> dict[TicketSystem, TicketSink]:
    """Only the two sinks that are real+testable get wired up automatically
    (`route/sinks/jira.py`, `linear.py`, `servicenow.py` are stubs — see
    their docstrings). A team resolved to one of those still routes fine at
    autonomy 0/1 (shadow/draft); it just can't auto-file until a real sink
    ships for it.
    """
    sinks: dict[TicketSystem, TicketSink] = {}
    if settings.webhook_url:
        sinks[TicketSystem.WEBHOOK] = WebhookSink(url=settings.webhook_url)
    if settings.github_token and settings.github_repo:
        sinks[TicketSystem.GITHUB] = GithubSink(
            token=settings.github_token, repo=settings.github_repo
        )
    return sinks


async def _run_route(
    settings: Settings, org_context: OrgContext, scan_run_id: uuid.UUID
) -> RouteOutcome:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    sinks = _build_sinks(settings)

    async with httpx.AsyncClient() as client, session_scope(session_factory) as session:
        finding_repo = FindingRepository(session)
        asset_repo = AssetRepository(session)
        ownership_repo = OwnershipRepository(session)
        verdict_repo = VerdictRepository(session)
        ticket_repo = TicketRepository(session)
        approval_repo = ApprovalRepository(session)

        findings = await finding_repo.list_for_scan_run_by_status(
            scan_run_id, FindingStatus.TRIAGED
        )
        outcome = await route_findings(
            org_context,
            findings,
            sinks=sinks,
            http_client=client,
            org_context_path=settings.org_context_path,
            asset_repo=asset_repo,
            ownership_repo=ownership_repo,
            verdict_repo=verdict_repo,
            finding_repo=finding_repo,
            ticket_repo=ticket_repo,
            approval_repo=approval_repo,
        )

    await engine.dispose()
    return outcome


route_app = typer.Typer(add_completion=False, help="Route true positives to tickets/approvals")
app.add_typer(route_app, name="route")


@route_app.command(name="run")
def route_run_cmd(
    scan_run: str = typer.Option(
        ..., "--scan-run", help="scan_run UUID whose TRIAGED findings to route"
    ),
) -> None:
    """Routes every TRIAGED true-positive finding from --scan-run: resolves
    assignee/cc/SLA against ownership + teams.yaml, renders + lints the
    ticket, and — per the category's autonomy level — shadows, drafts an
    approval, or auto-files. See Stage 7.
    """
    try:
        scan_run_id = uuid.UUID(scan_run)
    except ValueError:
        raise typer.BadParameter(f"--scan-run must be a UUID, got {scan_run!r}") from None

    settings = Settings()
    try:
        org_context = load_org_context(settings.org_context_path)
    except OrgContextError as exc:
        console.print(f"[red]org-context error:[/red] {exc}")
        raise typer.Exit(code=1) from None

    outcome = asyncio.run(_run_route(settings, org_context, scan_run_id))

    table = Table(title="kiyooo route")
    table.add_column("metric")
    table.add_column("count")
    table.add_row("shadowed (autonomy 0)", str(outcome.shadowed))
    table.add_row("drafted for approval", str(outcome.drafted))
    table.add_row("filed", str(outcome.filed))
    table.add_row("reopened", str(outcome.reopened))
    table.add_row("skipped (no TP verdict)", str(outcome.skipped_no_verdict))
    console.print(table)
    for violation in outcome.contract_violations:
        console.print(f"  [yellow]{violation}[/yellow]")


async def _list_approvals(settings: Settings) -> list[Approval]:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        rows = await ApprovalRepository(session).list_pending()
    await engine.dispose()
    return rows


async def _decide_approval(
    settings: Settings, approval_id: uuid.UUID, *, approve: bool, reviewer: str
) -> Approval:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        approval_repo = ApprovalRepository(session)
        approval = await approval_repo.decide(
            approval_id,
            status=ApprovalStatus.APPROVED if approve else ApprovalStatus.REJECTED,
            reviewer=reviewer,
            reviewed_at=datetime.now(UTC),
        )
        if approve:
            finding_repo = FindingRepository(session)
            await finding_repo.mark_status(approval.finding_id, FindingStatus.ROUTED)
    await engine.dispose()
    return approval


approvals_app = typer.Typer(add_completion=False, help="Human-in-the-loop approval queue")
route_app.add_typer(approvals_app, name="approvals")


@approvals_app.command(name="list")
def approvals_list_cmd() -> None:
    """PENDING drafts — nothing here has been sent to anyone. See
    `route approvals send`/`route approvals reject`.
    """
    settings = Settings()
    rows = asyncio.run(_list_approvals(settings))
    table = Table(title=f"{len(rows)} pending approval(s)")
    table.add_column("id")
    table.add_column("assignee")
    table.add_column("subject")
    for row in rows:
        table.add_row(
            str(row.id), row.target_assignee or "(unassigned)", row.rendered_subject or ""
        )
    console.print(table)


@approvals_app.command(name="send")
def approvals_send_cmd(
    approval_id: str = typer.Argument(...),
    reviewer: str = typer.Option(..., "--reviewer", help="Email of the human approving this"),
) -> None:
    """A human has read the draft and clicks send — invariant #6. This
    marks the finding ROUTED; wiring the approved draft to an actual sink
    call is the same `route/sinks/` machinery `route run` uses.
    """
    settings = Settings()
    approval = asyncio.run(
        _decide_approval(settings, uuid.UUID(approval_id), approve=True, reviewer=reviewer)
    )
    console.print(f"[green]approved[/green] {approval.id} by {reviewer}")


@approvals_app.command(name="reject")
def approvals_reject_cmd(
    approval_id: str = typer.Argument(...),
    reviewer: str = typer.Option(..., "--reviewer", help="Email of the human rejecting this"),
) -> None:
    settings = Settings()
    approval = asyncio.run(
        _decide_approval(settings, uuid.UUID(approval_id), approve=False, reviewer=reviewer)
    )
    console.print(f"[yellow]rejected[/yellow] {approval.id} by {reviewer}")


async def _close_ticket(settings: Settings, ticket_id: uuid.UUID) -> Ticket:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        ticket_repo = TicketRepository(session)
        finding_repo = FindingRepository(session)
        ticket = await ticket_repo.get(ticket_id)
        if ticket is None:
            raise ValueError(f"ticket {ticket_id} not found")
        # Closure-requires-proof: a closed ticket never jumps straight to
        # FIXED. It waits for `route recheck` to confirm the finding no
        # longer reproduces.
        await ticket_repo.set_status(ticket_id, "pending_verification")
        await finding_repo.mark_status(ticket.finding_id, FindingStatus.VERIFICATION_PENDING)
    await engine.dispose()
    return ticket


@route_app.command(name="close")
def route_close_cmd(ticket_id: str = typer.Argument(...)) -> None:
    """Closing a ticket moves its finding to verification_pending, never
    straight to fixed — see Stage 7's closure-requires-proof
    rule. Run `route recheck --scan-run <id>` after a fresh scan to confirm.
    """
    settings = Settings()
    ticket = asyncio.run(_close_ticket(settings, uuid.UUID(ticket_id)))
    console.print(f"[green]closed[/green] ticket {ticket.id} — finding is now verification_pending")


async def _run_recheck(
    settings: Settings, org_context: OrgContext, scan_run_id: uuid.UUID
) -> dict[str, int]:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    counts = {"fixed": 0, "regressed": 0, "no_longer_applicable": 0, "skipped": 0}

    async with session_scope(session_factory) as session:
        finding_repo = FindingRepository(session)
        asset_repo = AssetRepository(session)
        evidence_repo = EvidenceRepository(session)
        ticket_repo = TicketRepository(session)

        pending = await finding_repo.list_by_status(FindingStatus.VERIFICATION_PENDING)
        scan_evidence = await evidence_repo.for_scan_run(scan_run_id)
        evidence_by_asset: dict[uuid.UUID, list[object]] = {}
        for item in scan_evidence:
            evidence_by_asset.setdefault(item.asset_id, []).append(item)

        for finding in pending:
            if finding.asset_id not in evidence_by_asset:
                counts["skipped"] += 1
                continue
            asset = await asset_repo.get(finding.asset_id)
            if asset is None:
                counts["skipped"] += 1
                continue
            category = org_context.categories.get(finding.category_id)
            result = recheck_finding(
                finding,
                category,
                asset,
                evidence_by_asset[finding.asset_id],  # type: ignore[arg-type]
                now=datetime.now(UTC),
            )
            counts[result.value] += 1
            if result == RecheckResult.FIXED:
                finding.resolved_at = datetime.now(UTC)
                await finding_repo.mark_status(finding.id, FindingStatus.FIXED)
                ticket = await ticket_repo.get_by_finding(finding.id)
                if ticket is not None:
                    await ticket_repo.set_status(ticket.id, "closed")
            elif result == RecheckResult.REGRESSED:
                await finding_repo.mark_status(finding.id, FindingStatus.REGRESSED)
                ticket = await ticket_repo.get_by_finding(finding.id)
                if ticket is not None:
                    await ticket_repo.set_status(ticket.id, "open")

    await engine.dispose()
    return counts


@route_app.command(name="recheck")
def route_recheck_cmd(
    scan_run: str = typer.Option(
        ...,
        "--scan-run",
        help="scan_run UUID whose fresh evidence to re-check pending findings against",
    ),
) -> None:
    """Sweeps verification_pending findings and re-runs only their
    category's detect predicate against --scan-run's evidence. Only a clean
    re-check marks a finding fixed; it flips to regressed if it still
    matches. A finding whose asset --scan-run didn't touch is left pending.
    """
    try:
        scan_run_id = uuid.UUID(scan_run)
    except ValueError:
        raise typer.BadParameter(f"--scan-run must be a UUID, got {scan_run!r}") from None

    settings = Settings()
    try:
        org_context = load_org_context(settings.org_context_path)
    except OrgContextError as exc:
        console.print(f"[red]org-context error:[/red] {exc}")
        raise typer.Exit(code=1) from None

    counts = asyncio.run(_run_recheck(settings, org_context, scan_run_id))
    table = Table(title="kiyooo route recheck")
    table.add_column("outcome")
    table.add_column("count")
    for key, value in counts.items():
        table.add_row(key, str(value))
    console.print(table)


async def _run_escalate(settings: Settings) -> list[Ticket]:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        ticket_repo = TicketRepository(session)
        open_tickets = await ticket_repo.list_open()
        outcome = sweep_overdue(open_tickets, now=datetime.now(UTC))
        for ticket in outcome.to_escalate:
            await ticket_repo.set_status(ticket.id, "escalated")
    await engine.dispose()
    return outcome.to_escalate


@route_app.command(name="escalate")
def route_escalate_cmd() -> None:
    """Sweeps open tickets past their SLA due date and marks them escalated
    — a repeat run won't re-escalate the same ticket. Wiring this to notify
    each team's `escalation_after_sla` contact is a `route/sinks/` call away
    once a real Slack/email sink is configured; see Stage 7.
    """
    settings = Settings()
    escalated = asyncio.run(_run_escalate(settings))
    console.print(f"[yellow]{len(escalated)}[/yellow] ticket(s) escalated")
    for ticket in escalated:
        console.print(f"  {ticket.id} — assignee {ticket.assignee or '(unassigned)'}")


async def _run_digest(settings: Settings, since_hours: int) -> str:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    cutoff = datetime.now(UTC) - timedelta(hours=since_hours)
    async with session_scope(session_factory) as session:
        change_event_repo = ChangeEventRepository(session)
        finding_repo = FindingRepository(session)
        change_events = await change_event_repo.since(cutoff)
        routed = await finding_repo.list_by_status_since(FindingStatus.ROUTED, cutoff)
    await engine.dispose()

    text_body = render_digest_text(build_digest(change_events, routed))

    if settings.slack_webhook_url:
        async with httpx.AsyncClient() as client:
            await SlackSink(webhook_url=settings.slack_webhook_url).send(
                client, channel=None, subject="", body=text_body
            )
    return text_body


@route_app.command(name="digest")
def route_digest_cmd(
    hours: int = typer.Option(24, "--hours", help="Lookback window"),
) -> None:
    """Change events + newly routed true positives since --hours, posted to
    Slack if slack_webhook_url is configured, printed either way — so
    people aren't paged per-finding.
    """
    settings = Settings()
    text_body = asyncio.run(_run_digest(settings, hours))
    console.print(text_body)


async def _diff_since(settings: Settings, since: str) -> list[ChangeEvent]:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        scan_run_repo = ScanRunRepository(session)
        change_event_repo = ChangeEventRepository(session)

        try:
            run_id = uuid.UUID(since)
        except ValueError:
            try:
                cutoff = datetime.fromisoformat(since)
            except ValueError:
                raise typer.BadParameter(
                    f"--since must be a scan_run UUID or an ISO timestamp, got {since!r}"
                ) from None
        else:
            run = await scan_run_repo.get(run_id)
            if run is None:
                raise typer.BadParameter(f"no scan_run found with id {since}")
            cutoff = run.started_at

        events = await change_event_repo.since(cutoff)
    await engine.dispose()
    return events


@app.command(name="diff")
def diff_cmd(
    since: str = typer.Option(..., "--since", help="scan_run UUID or an ISO timestamp"),
) -> None:
    """Show change_events recorded since a given scan run or timestamp."""
    settings = Settings()
    events = asyncio.run(_diff_since(settings, since))
    _render_change_events(events)


assets_app = typer.Typer(add_completion=False, help="Query the asset graph")
app.add_typer(assets_app, name="assets")


async def _query_assets(settings: Settings, clauses: list[str]) -> list[Asset]:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        assets = await query_assets(session, clauses)
    await engine.dispose()
    return assets


@assets_app.command(name="query")
def assets_query_cmd(
    clauses: list[str] = typer.Argument(
        ..., help="field=value or field!=value clauses, ANDed (fields: type, is_active, value)"
    ),
) -> None:
    settings = Settings()
    try:
        assets = asyncio.run(_query_assets(settings, clauses))
    except QueryError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from None
    _render_assets(assets)


async def _decommission_candidates(settings: Settings) -> list[Asset]:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        scan_run_repo = ScanRunRepository(session)
        assets = await decommission_candidates(session, scan_run_repo)
    await engine.dispose()
    return assets


@assets_app.command(name="decommission-candidates")
def assets_decommission_candidates_cmd() -> None:
    """Reachable, unowned (no attribution >=0.8 confidence), and unchanged for
    3 consecutive scans. A lead list for human review — never an autonomous
    action — and evaluates 3 of the design's 4 conditions: "serves no traffic
    signal" has no data source in this schema yet, see graph/queries.py.
    """
    settings = Settings()
    assets = asyncio.run(_decommission_candidates(settings))
    console.print(
        "[dim]Lead list for human review, not an autonomous action. Evaluates 3 of "
        "4 the design doc conditions — no traffic-signal data source exists yet.[/dim]"
    )
    _render_assets(assets)


async def _run_enrich(
    settings: Settings,
    org_context: OrgContext,
    *,
    terraform_state_path: Path | None,
    codeowners_path: Path | None,
    iac_repo_path: Path | None,
    iac_manifest_file: str | None,
    skip_cloud: bool,
) -> tuple[int, int, int, int]:
    """Returns (total active assets, resolved, disputed, orphan)."""
    logger = get_logger()
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)

    cloud_matches: list[CloudResourceMatch] = []
    if not skip_cloud:
        try:
            import boto3

            aws_session = boto3.Session()
            cloud_matches = enumerate_all(
                ec2_client=aws_session.client("ec2"),
                elbv2_client=aws_session.client("elbv2"),
                s3_client=aws_session.client("s3"),
                cloudfront_client=aws_session.client("cloudfront"),
                sts_client=aws_session.client("sts"),
            )
        except Exception as exc:  # noqa: BLE001 -- AWS being unavailable isn't fatal here
            logger.warning("enrich.aws_unavailable", error=str(exc))

    terraform_resources: list[TerraformResource] = []
    if terraform_state_path is not None:
        raw_state = await asyncio.to_thread(terraform_state_path.read_bytes)
        terraform_resources = parse_terraform_state(raw_state)
    codeowners: list[tuple[str, str]] = []
    if codeowners_path is not None:
        raw_codeowners = await asyncio.to_thread(codeowners_path.read_bytes)
        codeowners = parse_codeowners(raw_codeowners)

    ctx = OwnershipEnrichmentContext(
        org_context=org_context,
        cloud_matches=cloud_matches,
        terraform_resources=terraform_resources,
        codeowners=codeowners,
        iac_repo_path=iac_repo_path,
        iac_manifest_file=iac_manifest_file,
        email_to_owner=build_email_to_team_map(org_context.teams.teams),
    )

    total = resolved = disputed = orphan = 0
    async with session_scope(session_factory) as session:
        asset_repo = AssetRepository(session)
        ownership_repo = OwnershipRepository(session)
        evidence_repo = EvidenceRepository(session)

        for asset in await asset_repo.list_active():
            total += 1
            asset_evidence = await evidence_repo.for_asset(asset.id)
            apply_tech(asset, asset_evidence)
            apply_ai_tech(asset, asset_evidence)

            result = await resolve_ownership(asset, ctx, asset_repo, ownership_repo)
            if result.outcome == MergeOutcome.RESOLVED:
                resolved += 1
            elif result.outcome == MergeOutcome.DISPUTED:
                disputed += 1
            else:
                orphan += 1

    await engine.dispose()
    return total, resolved, disputed, orphan


@app.command()
def enrich(
    terraform_state: Path | None = typer.Option(
        None, "--terraform-state", help="Path to a raw terraform.tfstate JSON file"
    ),
    codeowners: Path | None = typer.Option(None, "--codeowners", help="Path to a CODEOWNERS file"),
    iac_repo: Path | None = typer.Option(
        None, "--iac-repo", help="Local checkout of the IaC repo (enables the git-blame source)"
    ),
    iac_manifest: str | None = typer.Option(
        None, "--iac-manifest", help="Manifest file path within --iac-repo to attribute by"
    ),
    skip_cloud: bool = typer.Option(
        False, "--skip-cloud", help="Skip AWS enrichment even if credentials are available"
    ),
) -> None:
    """Cloud tags, tech fingerprints, and ownership resolution. Reads AWS via
    the default credential chain if available and not skipped — the
    org-context and DB-only ownership sources (manual, teams.yaml pattern,
    sibling asset) always run regardless.
    """
    settings = Settings()
    try:
        org_context = load_org_context(settings.org_context_path)
    except OrgContextError as exc:
        console.print(f"[red]org-context error:[/red] {exc}")
        raise typer.Exit(code=1) from None

    total, resolved, disputed, orphan = asyncio.run(
        _run_enrich(
            settings,
            org_context,
            terraform_state_path=terraform_state,
            codeowners_path=codeowners,
            iac_repo_path=iac_repo,
            iac_manifest_file=iac_manifest,
            skip_cloud=skip_cloud,
        )
    )

    table = Table(title="kiyooo enrich")
    table.add_column("metric")
    table.add_column("count")
    table.add_row("total active assets", str(total))
    table.add_row("resolved (>=0.8, unambiguous)", str(resolved))
    table.add_row("disputed", str(disputed))
    table.add_row("orphan", str(orphan))
    console.print(table)

    if total:
        pct = round(100 * resolved / total, 1)
        console.print(f"[dim]{pct}% resolved at >=0.8 confidence (DoD target: >=80%)[/dim]")


async def _assets_by_ownership_outcome(settings: Settings, outcome: MergeOutcome) -> list[Asset]:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    matches: list[Asset] = []
    async with session_scope(session_factory) as session:
        asset_repo = AssetRepository(session)
        ownership_repo = OwnershipRepository(session)
        for asset in await asset_repo.list_active():
            result = await merge_existing(asset.id, ownership_repo)
            if result.outcome == outcome:
                matches.append(asset)
    await engine.dispose()
    return matches


@assets_app.command(name="orphans")
def assets_orphans_cmd() -> None:
    """Active assets with no ownership resolution >=0.8 confidence. Reads
    whatever `kiyooo enrich` last found — run that first.
    """
    settings = Settings()
    assets = asyncio.run(_assets_by_ownership_outcome(settings, MergeOutcome.ORPHAN))
    _render_assets(assets)


@assets_app.command(name="disputed-ownership")
def assets_disputed_ownership_cmd() -> None:
    """Assets where the top two ownership sources both hit >=0.8 confidence
    and disagree — never auto-resolved, always surfaced for a human.
    """
    settings = Settings()
    assets = asyncio.run(_assets_by_ownership_outcome(settings, MergeOutcome.DISPUTED))
    _render_assets(assets)


async def _attack_paths(settings: Settings, org_context: OrgContext) -> list[AttackPath]:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        sensitive_category_ids = {
            c.id for c in org_context.categories.values() if c.is_sensitive_target
        }
        assets = await AssetRepository(session).list_all(limit=100_000)
        edges = await AssetEdgeRepository(session).list_all(limit=100_000)
        findings = await FindingRepository(session).list_all(limit=100_000)
        paths = find_attack_paths(
            assets, edges, findings, sensitive_category_ids=sensitive_category_ids
        )
    await engine.dispose()
    return paths


@app.command(name="attack-paths")
def attack_paths_cmd() -> None:
    """Stage 17 — one correlated path per sensitive finding
    (`is_sensitive_target: true` category) reachable from another active
    finding, instead of N unrelated findings. Computed on demand from the
    current graph/finding state, not a persisted table — see
    graph/attack_path.py's module docstring.
    """
    settings = Settings()
    try:
        org_context = load_org_context(settings.org_context_path)
    except OrgContextError as exc:
        raise typer.BadParameter(f"org-context error: {exc}") from None

    paths = asyncio.run(_attack_paths(settings, org_context))
    if not paths:
        console.print("[dim]No attack paths found.[/dim]")
        return

    for i, path in enumerate(paths, start=1):
        table = Table(title=f"Path {i} — score {path.score} — {path.sensitive_category_id}")
        table.add_column("asset_type")
        table.add_column("asset_value")
        table.add_column("finding_category")
        table.add_column("severity")
        for hop in path.hops:
            table.add_row(
                hop.asset_type,
                hop.asset_value,
                hop.finding_category_id or "",
                hop.finding_severity or "",
            )
        console.print(table)


modules_app = typer.Typer(add_completion=False, help="Turn optional attack-surface modules on/off")
app.add_typer(modules_app, name="modules")


async def _list_module_toggles(settings: Settings) -> list[ModuleToggle]:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        toggles = await ModuleToggleRepository(session).list_all()
    await engine.dispose()
    return toggles


@modules_app.command(name="list")
def modules_list() -> None:
    """Same API the web UI's Settings page uses — GET /api/module-toggles."""
    settings = Settings()
    toggles = asyncio.run(_list_module_toggles(settings))
    table = Table(title="attack-surface modules")
    table.add_column("module")
    table.add_column("enabled")
    for toggle in toggles:
        table.add_row(toggle.module_key, "yes" if toggle.enabled else "no")
    console.print(table)


async def _set_module_toggle(settings: Settings, module_key: str, enabled: bool) -> ModuleToggle:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        toggle = await ModuleToggleRepository(session).set_enabled(
            module_key, enabled=enabled, updated_at=datetime.now(UTC)
        )
    await engine.dispose()
    return toggle


@modules_app.command(name="enable")
def modules_enable(module_key: str) -> None:
    """Turn on a module's nav entry and page — cloud, containers, repos,
    mobile, or attack_paths. Purely a UI gate: the API, CLI, and ingest
    pipeline for that domain work regardless of this setting.
    """
    if module_key not in MODULE_KEYS:
        raise typer.BadParameter(f"unknown module {module_key!r} — one of {MODULE_KEYS}")
    settings = Settings()
    asyncio.run(_set_module_toggle(settings, module_key, True))
    console.print(f"[green]{module_key} enabled[/green]")


@modules_app.command(name="disable")
def modules_disable(module_key: str) -> None:
    """Turn off a module's nav entry and page. See `modules enable`."""
    if module_key not in MODULE_KEYS:
        raise typer.BadParameter(f"unknown module {module_key!r} — one of {MODULE_KEYS}")
    settings = Settings()
    asyncio.run(_set_module_toggle(settings, module_key, False))
    console.print(f"[yellow]{module_key} disabled[/yellow]")


async def _run_detect(
    settings: Settings,
    org_context: OrgContext,
    scan_run_id: uuid.UUID,
    *,
    kev_file: Path | None,
    epss_file: Path | None,
    fetch_live: bool,
) -> DetectionOutcome:
    logger = get_logger()
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)

    kev_catalog: KevCatalog | None = None
    epss_scores: dict[str, EpssScore] = {}

    async with session_scope(session_factory) as session:
        evidence_repo = EvidenceRepository(session)
        asset_repo = AssetRepository(session)
        control_repo = ControlRepository(session)
        finding_repo = FindingRepository(session)
        finding_evidence_repo = FindingEvidenceRepository(session)

        scan_evidence = await evidence_repo.for_scan_run(scan_run_id)
        touched_asset_ids = {item.asset_id for item in scan_evidence}
        resolved_assets = [await asset_repo.get(aid) for aid in touched_asset_ids]
        assets = [asset for asset in resolved_assets if asset is not None]

        if kev_file is not None:
            kev_catalog = parse_kev_catalog(await asyncio.to_thread(kev_file.read_bytes))
        elif fetch_live:
            try:
                async with httpx.AsyncClient() as client:
                    kev_catalog = await fetch_kev_catalog(client)
            except Exception as exc:  # noqa: BLE001 -- KEV being unreachable isn't fatal
                logger.warning("detect.kev_unavailable", error=str(exc))

        cve_ids = sorted(
            {
                cve_id
                for item in scan_evidence
                if item.kind == EvidenceKind.NUCLEI_RESULT
                for cve_id in cve_ids_from_nuclei_record(item.content_inline or {})
            }
        )
        if epss_file is not None:
            epss_scores = parse_epss_response(await asyncio.to_thread(epss_file.read_bytes))
        elif fetch_live and cve_ids:
            try:
                async with httpx.AsyncClient() as client:
                    epss_scores = await fetch_epss_scores(client, cve_ids)
            except Exception as exc:  # noqa: BLE001 -- EPSS being unreachable isn't fatal
                logger.warning("detect.epss_unavailable", error=str(exc))

        outcome = await run_detection(
            org_context,
            assets,
            scan_run_id=scan_run_id,
            evidence_repo=evidence_repo,
            control_repo=control_repo,
            finding_repo=finding_repo,
            finding_evidence_repo=finding_evidence_repo,
            kev_catalog=kev_catalog,
            epss_scores=epss_scores,
        )

    await engine.dispose()
    return outcome


async def _latest_scan_run_id(settings: Settings) -> uuid.UUID | None:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        recent = await ScanRunRepository(session).recent_completed(1)
    await engine.dispose()
    return recent[0].id if recent else None


async def _run_pipeline_chain(
    settings: Settings, org_context: OrgContext, scan_run_id: uuid.UUID
) -> tuple[DetectionOutcome, RouteOutcome]:
    """detect -> triage -> route against one scan_run's evidence — the
    single chain both `kiyooo events handle` and every scheduled
    `worker/tasks.py` job run, so a fix to one step is a fix everywhere it
    runs. See Stage 11's event-trigger deliverable.
    """
    kev_file = settings.kev_cache_path if settings.kev_cache_path.exists() else None
    detect_outcome = await _run_detect(
        settings, org_context, scan_run_id, kev_file=kev_file, epss_file=None, fetch_live=True
    )
    await _run_triage(settings, org_context, scan_run_id, active=False)
    route_outcome = await _run_route(settings, org_context, scan_run_id)
    return detect_outcome, route_outcome


async def _run_event_triggered_scan(
    settings: Settings, org_context: OrgContext, value: str, *, active: bool
) -> tuple[uuid.UUID | None, DetectionOutcome | None, RouteOutcome | None]:
    # A newly-discovered asset's exposed surface is exactly what needs
    # port discovery, not just an HTTP probe against 80/443 — DEEP (which
    # includes naabu's PORTSCAN stage) whenever --active is authorized,
    # same as `kiyooo scan --profile deep --active` would use. Without
    # --active, STANDARD is still the ceiling — PORTSCAN is an active stage.
    profile = ScanProfile.DEEP if active else ScanProfile.STANDARD
    await _run_scan(settings, org_context, [value], profile, active=active, dry_run=False)
    scan_run_id = await _latest_scan_run_id(settings)
    if scan_run_id is None:
        return None, None, None
    detect_outcome, route_outcome = await _run_pipeline_chain(settings, org_context, scan_run_id)
    return scan_run_id, detect_outcome, route_outcome


events_app = typer.Typer(add_completion=False, help="Event-triggered targeted scans")
app.add_typer(events_app, name="events")


@events_app.command(name="handle")
def events_handle_cmd(
    value: str = typer.Argument(..., help="The new asset's value, e.g. a hostname or IP"),
    kind: str = typer.Option(
        "deploy", "--kind", help="dns_record | cloud_resource | repo | deploy — informational"
    ),
    active: bool = typer.Option(
        False, "--active", help="Same authorization gates as `kiyooo scan --active`"
    ),
) -> None:
    """Targeted mini-scan of exactly one newly-discovered asset, chained
    straight through detect -> triage -> route in one process — the design
    Stage 11's event-trigger deliverable ("new cloud resource, new DNS
    record, new repo, CI/CD deploy webhook -> targeted mini-scan of just
    the new asset"). An external relay (an EventBridge rule, a GitHub
    webhook receiver, a CI deploy hook) is expected to invoke this — this
    command is the trigger's target, not a listener itself; Stage 10's API
    gives it an HTTP front door.
    """
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

    scan_run_id, detect_outcome, route_outcome = asyncio.run(
        _run_event_triggered_scan(settings, org_context, value, active=active)
    )

    if scan_run_id is None:
        console.print(f"[red]no scan_run recorded for event kind={kind!r} value={value!r}[/red]")
        raise typer.Exit(code=1)

    table = Table(title=f"kiyooo events handle — {kind}:{value}")
    table.add_column("metric")
    table.add_column("value")
    table.add_row("scan_run_id", str(scan_run_id))
    if detect_outcome is not None:
        table.add_row("findings created/updated", str(detect_outcome.created_or_updated))
    if route_outcome is not None:
        table.add_row("filed", str(route_outcome.filed))
        table.add_row("drafted", str(route_outcome.drafted))
        table.add_row("shadowed", str(route_outcome.shadowed))
    console.print(table)


@app.command(name="detect")
def detect_cmd(
    scan_run: str = typer.Option(..., "--scan-run", help="scan_run UUID to run detection over"),
    kev_file: Path | None = typer.Option(
        None, "--kev-file", help="Local CISA KEV catalog JSON (skips the live fetch)"
    ),
    epss_file: Path | None = typer.Option(
        None, "--epss-file", help="Local FIRST EPSS response JSON (skips the live fetch)"
    ),
    no_live_feeds: bool = typer.Option(
        False,
        "--no-live-feeds",
        help="Never fetch KEV/EPSS live; run without them if no file given",
    ),
) -> None:
    """Evaluate every enabled category against every asset touched by
    --scan-run, applying controls.yaml suppression before any finding is
    created. cve_in_kev/epss_above only fire if a KEV/EPSS source is
    available — a local --kev-file/--epss-file, or (default) a live fetch
    of CISA's and FIRST's public feeds.
    """
    try:
        scan_run_id = uuid.UUID(scan_run)
    except ValueError:
        raise typer.BadParameter(f"--scan-run must be a UUID, got {scan_run!r}") from None

    settings = Settings()
    try:
        org_context = load_org_context(settings.org_context_path)
    except OrgContextError as exc:
        console.print(f"[red]org-context error:[/red] {exc}")
        raise typer.Exit(code=1) from None

    outcome = asyncio.run(
        _run_detect(
            settings,
            org_context,
            scan_run_id,
            kev_file=kev_file,
            epss_file=epss_file,
            fetch_live=not no_live_feeds,
        )
    )

    table = Table(title="kiyooo detect")
    table.add_column("metric")
    table.add_column("count")
    table.add_row("findings created/updated", str(outcome.created_or_updated))
    table.add_row("suppressed", str(outcome.suppressed))
    table.add_row("evaluated, no match", str(outcome.skipped_no_match))
    console.print(table)


categories_app = typer.Typer(add_completion=False, help="Validate and test category YAML")
app.add_typer(categories_app, name="categories")


def _iter_predicate_names(category: object) -> list[str]:
    from kiyooo.config import CategoryDefinition, ControlDefinition

    if isinstance(category, CategoryDefinition):
        clauses = [*category.detect.all_of, *category.detect.any_of, *category.suppress_if]
    elif isinstance(category, ControlDefinition):
        clauses = [*category.detect.all_of, *category.detect.any_of]
    else:
        return []
    names: list[str] = []
    for clause in clauses:
        ((name, _),) = clause.items()
        names.append(name)
    return names


@categories_app.command(name="lint")
def categories_lint_cmd() -> None:
    """Every predicate name referenced in detect/suppress_if blocks must be
    one `detect/predicates.py` actually implements — config.py's Pydantic
    validation checks shape (regex syntax, required fields) but has no way
    to know the set of valid predicate names, so this closes that gap.
    """
    settings = Settings()
    try:
        org_context = load_org_context(settings.org_context_path)
    except OrgContextError as exc:
        console.print(f"[red]org-context error:[/red] {exc}")
        raise typer.Exit(code=1) from None

    unknown: list[tuple[str, str]] = []
    for category in org_context.categories.values():
        for name in _iter_predicate_names(category):
            if name not in PREDICATES:
                unknown.append((category.id, name))
    for control in org_context.controls.controls:
        for name in _iter_predicate_names(control):
            if name not in PREDICATES:
                unknown.append((f"control:{control.id}", name))

    if unknown:
        console.print("[red]unknown predicates referenced:[/red]")
        for source_id, name in unknown:
            console.print(f"  {source_id}: {name!r}")
        raise typer.Exit(code=1)

    # Stage 7's ticket contract: "add a template linter to `categories lint`"
    # — a template that can't render, or that renders without one of the six
    # required blocks, is a template bug, not something discovered the first
    # time a real ticket gets filed.
    template_errors: list[str] = []
    for category in org_context.categories.values():
        template_path = (
            settings.org_context_path / category.route.ticket_template
            if category.route.ticket_template
            else None
        )
        context = dummy_context(category_name=category.name)
        try:
            body = render_ticket_body(context, template_path=template_path)
        except Exception as exc:  # noqa: BLE001 -- any template error is a lint failure
            template_errors.append(f"{category.id}: template failed to render: {exc}")
            continue
        missing = lint_ticket_body(body)
        if missing:
            template_errors.append(f"{category.id}: ticket template missing block(s): {missing}")

    if template_errors:
        console.print("[red]ticket template contract violations:[/red]")
        for error in template_errors:
            console.print(f"  {error}")
        raise typer.Exit(code=1)

    console.print(
        f"[green]OK[/green] — {len(org_context.categories)} categories, "
        f"{len(org_context.controls.controls)} controls, all predicate names known, "
        "all ticket templates satisfy the six-block contract"
    )


@categories_app.command(name="test")
def categories_test_cmd() -> None:
    """Runs each category's `<id>.cases.yaml` should-match/should-not-match
    fixtures (`detect/cases.py`) against its own `detect:` block — pure,
    no DB, no LLM. A category with no `.cases.yaml` sibling is skipped, not
    failed, since org-context ships incrementally.
    """
    settings = Settings()
    try:
        org_context = load_org_context(settings.org_context_path)
    except OrgContextError as exc:
        console.print(f"[red]org-context error:[/red] {exc}")
        raise typer.Exit(code=1) from None

    total_pass = total_fail = total_skipped = 0
    failures: list[str] = []

    for category in org_context.categories.values():
        cases_path = cases_path_for(category.source_file)
        if not cases_path.exists():
            total_skipped += 1
            continue
        cases = load_cases(cases_path)

        for label, case_list, want_match in (
            ("should_match", cases.should_match, True),
            ("should_not_match", cases.should_not_match, False),
        ):
            for case in case_list:
                asset = build_asset(case.asset)
                evidence = build_evidence(asset.id, case.evidence)
                ctx = build_context(case)
                try:
                    matched = evaluate_block(category.detect, asset, evidence, ctx) is not None
                except UnknownPredicateError as exc:
                    matched = False
                    failures.append(f"{category.id}/{label}/{case.name or '(unnamed)'}: {exc}")
                    total_fail += 1
                    continue
                if matched == want_match:
                    total_pass += 1
                else:
                    total_fail += 1
                    failures.append(
                        f"{category.id}/{label}/{case.name or '(unnamed)'}: "
                        f"expected match={want_match}, got {matched}"
                    )

    console.print(
        f"[green]{total_pass} passed[/green], "
        f"[red]{total_fail} failed[/red], "
        f"{total_skipped} categories skipped (no .cases.yaml)"
    )
    for failure in failures:
        console.print(f"  [red]FAIL[/red] {failure}")
    if total_fail:
        raise typer.Exit(code=1)


eval_app = typer.Typer(add_completion=False, help="Triage accuracy evaluation")
app.add_typer(eval_app, name="eval")

_DEFAULT_EVAL_CORPUS = Path(__file__).parent.parent / "tests" / "eval" / "corpus"


def _build_eval_provider(provider_name: str, settings: Settings) -> LlmProvider:
    if provider_name == "ollama":
        return OllamaProvider(base_url=settings.llm_base_url)
    if provider_name == "anthropic":
        if not settings.anthropic_api_key:
            raise typer.BadParameter("anthropic_api_key is not configured")
        return AnthropicProvider(settings.anthropic_api_key)
    raise typer.BadParameter(
        f"eval run only supports ollama/anthropic today, got {provider_name!r}"
    )


@eval_app.command(name="run")
def eval_run_cmd(
    provider: str = typer.Option(..., "--provider", help="ollama | anthropic"),
    model: str = typer.Option(..., "--model", help="Model name to evaluate"),
    corpus_path: Path = typer.Option(
        _DEFAULT_EVAL_CORPUS, "--corpus", help="Directory of labeled *.yaml eval cases"
    ),
) -> None:
    """Runs a labeled corpus through one model's bulk-pass adjudication and
    reports precision, high/critical recall, critical-miss rate, cost, and
    latency. This calls a real model — it is never run
    as part of the test suite, and it is not run automatically by any
    other command.

    The corpus shipped in tests/eval/corpus/ is a small, hand-labeled set
    built to exercise this harness end-to-end. It is illustrative, not a
    genuine accuracy benchmark — the DoD's recall/precision/critical-miss
    thresholds are only meaningful measured against ~100+ real labeled
    findings from your own scans, which this repository has none of yet.
    """
    settings = Settings()
    try:
        org_context = load_org_context(settings.org_context_path)
    except OrgContextError as exc:
        console.print(f"[red]org-context error:[/red] {exc}")
        raise typer.Exit(code=1) from None

    corpus = load_corpus(corpus_path)
    if not corpus.cases:
        console.print(f"[red]no cases found in {corpus_path}[/red]")
        raise typer.Exit(code=1)

    llm_provider = _build_eval_provider(provider, settings)
    skills = load_skills(settings.org_context_path / "skills")
    results = asyncio.run(
        run_eval(
            corpus,
            org_context.categories,
            llm_provider,
            model,
            provider_name=provider,
            org_name=org_context.scope.org_name,
            skills=skills,
        )
    )
    metrics = compute_metrics(results)

    console.print(
        "[yellow]Illustrative corpus — not a substitute for the DoD's real labeled-findings "
        "benchmark.[/yellow]"
    )
    table = Table(title=f"kiyooo eval run — {provider}/{model}")
    table.add_column("metric")
    table.add_column("value")
    table.add_row("cases", str(metrics.total_cases))
    table.add_row("precision", f"{metrics.precision:.2f}")
    table.add_row("recall (high/critical)", f"{metrics.recall_high_critical:.2f}")
    table.add_row("critical-miss rate", f"{metrics.critical_miss_rate:.2f}")
    table.add_row("mean cost/finding (USD)", f"${metrics.mean_cost_usd:.4f}")
    table.add_row("p50 latency (ms)", f"{metrics.p50_latency_ms:.0f}")
    table.add_row("p95 latency (ms)", f"{metrics.p95_latency_ms:.0f}")
    console.print(table)


_SOURCE_SYSTEMS = {
    "mandiant": ExternalFindingSystem.MANDIANT_ASM,
    "tenable": ExternalFindingSystem.TENABLE,
}


def _open_ingest_scan_run(scan_run_id: uuid.UUID) -> ScanRun:
    now = datetime.now(UTC)
    return ScanRun(
        id=scan_run_id,
        started_at=now,
        finished_at=now,
        status=ScanRunStatus.COMPLETED,
        scope_hash="ingest",
        config_hash="ingest",
        trigger=ScanTrigger.INGEST,
    )


async def _run_ingest_source(
    settings: Settings, org_context: OrgContext, source: str, since: str | None
) -> IngestOutcome:
    system = _SOURCE_SYSTEMS[source]
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)

    async with httpx.AsyncClient() as client:
        if source == "mandiant":
            if not settings.mandiant_api_key:
                raise typer.BadParameter("mandiant_api_key is not configured")
            raw_items = await mandiant_adapter.fetch_issues(
                client, api_key=settings.mandiant_api_key, since=since
            )
            imported = [mandiant_adapter.parse_issue(item) for item in raw_items]
        elif source == "tenable":
            if not (settings.tenable_access_key and settings.tenable_secret_key):
                raise typer.BadParameter("tenable_access_key/tenable_secret_key are not configured")
            raw_items = await tenable_adapter.fetch_vulnerabilities(
                client,
                access_key=settings.tenable_access_key,
                secret_key=settings.tenable_secret_key,
            )
            imported = [tenable_adapter.parse_vulnerability(item) for item in raw_items]
        else:
            raise typer.BadParameter(f"unknown --source {source!r}")

    async with session_scope(session_factory) as session:
        source_repo = ExternalFindingSourceRepository(session)
        external_finding_repo = ExternalFindingRawRepository(session)
        asset_repo = AssetRepository(session)
        evidence_repo = EvidenceRepository(session)
        finding_repo = FindingRepository(session)
        finding_evidence_repo = FindingEvidenceRepository(session)
        scan_run_repo = ScanRunRepository(session)

        source_row = await source_repo.get_or_create(system)
        scan_run_id = uuid.uuid4()
        await scan_run_repo.add(_open_ingest_scan_run(scan_run_id))

        outcome = await ingest_batch(
            imported,
            source_id=source_row.id,
            source_label=source,
            scan_run_id=scan_run_id,
            org_context=org_context,
            asset_repo=asset_repo,
            evidence_repo=evidence_repo,
            finding_repo=finding_repo,
            finding_evidence_repo=finding_evidence_repo,
            external_finding_repo=external_finding_repo,
        )
        await source_repo.update_watermark(source_row.id, synced_at=datetime.now(UTC), cursor=since)

    await engine.dispose()
    return outcome


async def _run_ingest_file(
    settings: Settings,
    org_context: OrgContext,
    file_path: Path,
    fmt: str,
    csv_asset_col: str | None,
    csv_issue_type_col: str | None,
    csv_asset_type: str | None,
) -> IngestOutcome:
    raw = await asyncio.to_thread(file_path.read_bytes)
    if fmt == "nuclei":
        imported = parse_jsonl(raw)
        source_label = "nuclei-file"
        system = ExternalFindingSystem.NUCLEI_JSON
    elif fmt == "csv":
        if not (csv_asset_col and csv_issue_type_col and csv_asset_type):
            raise typer.BadParameter(
                "--csv-asset-col, --csv-issue-type-col, and --csv-asset-type are "
                "required with --format csv"
            )
        columns = CsvColumnMapping(asset_col=csv_asset_col, issue_type_col=csv_issue_type_col)
        imported = parse_csv(raw, asset_type=AssetType(csv_asset_type), columns=columns)
        source_label = "csv-file"
        system = ExternalFindingSystem.CUSTOM
    else:
        raise typer.BadParameter(f"unsupported --format {fmt!r} (nuclei | csv)")

    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        source_repo = ExternalFindingSourceRepository(session)
        external_finding_repo = ExternalFindingRawRepository(session)
        asset_repo = AssetRepository(session)
        evidence_repo = EvidenceRepository(session)
        finding_repo = FindingRepository(session)
        finding_evidence_repo = FindingEvidenceRepository(session)
        scan_run_repo = ScanRunRepository(session)

        source_row = await source_repo.get_or_create(system)
        scan_run_id = uuid.uuid4()
        await scan_run_repo.add(_open_ingest_scan_run(scan_run_id))

        outcome = await ingest_batch(
            imported,
            source_id=source_row.id,
            source_label=source_label,
            scan_run_id=scan_run_id,
            org_context=org_context,
            asset_repo=asset_repo,
            evidence_repo=evidence_repo,
            finding_repo=finding_repo,
            finding_evidence_repo=finding_evidence_repo,
            external_finding_repo=external_finding_repo,
        )

    await engine.dispose()
    return outcome


ingest_app = typer.Typer(add_completion=False, help="Import findings from external vendors/files")
app.add_typer(ingest_app, name="ingest")


@ingest_app.command(name="run")
def ingest_run_cmd(
    source: str | None = typer.Option(None, "--source", help="mandiant | tenable"),
    since: str | None = typer.Option(None, "--since", help="ISO date/timestamp watermark"),
    file: Path | None = typer.Option(None, "--file", help="Local file to import"),
    fmt: str | None = typer.Option(None, "--format", help="nuclei | csv"),
    csv_asset_col: str | None = typer.Option(None, "--csv-asset-col"),
    csv_issue_type_col: str | None = typer.Option(None, "--csv-issue-type-col"),
    csv_asset_type: str | None = typer.Option(
        None, "--csv-asset-type", help="Asset type name, e.g. ip, subdomain, http_service"
    ),
) -> None:
    """Import findings from a vendor API (--source) or a local file
    (--file --format). We ingest vendor findings; we never inherit their
    severity — that always comes from our own category match via
    vendor_mapping.yaml. See `kiyooo ingest unmapped` for gaps.
    """
    settings = Settings()
    try:
        org_context = load_org_context(settings.org_context_path)
    except OrgContextError as exc:
        console.print(f"[red]org-context error:[/red] {exc}")
        raise typer.Exit(code=1) from None

    if bool(source) == bool(file):
        raise typer.BadParameter("specify exactly one of --source or --file")

    if source:
        outcome = asyncio.run(_run_ingest_source(settings, org_context, source, since))
    else:
        assert file is not None
        if not fmt:
            raise typer.BadParameter("--format is required with --file")
        outcome = asyncio.run(
            _run_ingest_file(
                settings, org_context, file, fmt, csv_asset_col, csv_issue_type_col, csv_asset_type
            )
        )

    table = Table(title="kiyooo ingest")
    table.add_column("metric")
    table.add_column("count")
    table.add_row("mapped", str(outcome.mapped))
    table.add_row("unmapped", str(outcome.unmapped))
    console.print(table)


async def _list_unmapped(settings: Settings) -> list[ExternalFindingRaw]:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        repo = ExternalFindingRawRepository(session)
        rows = await repo.list_unmapped()
    await engine.dispose()
    return rows


@ingest_app.command(name="unmapped")
def ingest_unmapped_cmd() -> None:
    """Vendor issue types with no vendor_mapping.yaml entry — a work item
    to write a mapping (or a category) for, not a silent drop.
    """
    settings = Settings()
    rows = asyncio.run(_list_unmapped(settings))
    table = Table(title=f"{len(rows)} unmapped external finding(s)")
    table.add_column("external_id")
    table.add_column("notes")
    for row in rows:
        table.add_row(row.external_id, row.mapping_notes or "")
    console.print(table)


sources_app = typer.Typer(
    add_completion=False,
    help="Config-driven connections to any REST/JSON-emitting ASM/VM tool — "
    "no code change needed to onboard one (see ingest/adapters/generic_rest.py)",
)
ingest_app.add_typer(sources_app, name="sources")


async def _sources_add(name: str, config: GenericRestConfig) -> uuid.UUID:
    settings = Settings()
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        source = await ExternalFindingSourceRepository(session).create(
            name=name,
            system=ExternalFindingSystem.CUSTOM,
            config=config.model_dump(mode="json"),
            enabled=True,
        )
        source_id = source.id
    await engine.dispose()
    return source_id


@sources_app.command(name="add")
def sources_add_cmd(
    name: str = typer.Option(..., "--name", help="Human label, e.g. 'Prod Qualys tenant'"),
    config_file: Path = typer.Option(
        ..., "--config", help="YAML/JSON file matching GenericRestConfig's shape"
    ),
) -> None:
    """See `docs/ingest-source-config.example.yaml` for the shape (base
    URL, auth via credential_ref, and a dotted-path field mapping).
    """
    try:
        raw = yaml.safe_load(config_file.read_text())
        config = GenericRestConfig.model_validate(raw)
    except (yaml.YAMLError, PydanticValidationError, OSError) as exc:
        console.print(f"[red]invalid source config:[/red] {exc}")
        raise typer.Exit(code=1) from None

    source_id = asyncio.run(_sources_add(name, config))
    console.print(f"[green]created ingest source[/green] {name!r} — id={source_id}")


async def _sources_list() -> list[ExternalFindingSource]:
    settings = Settings()
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        sources = await ExternalFindingSourceRepository(session).list_all()
    await engine.dispose()
    return sources


@sources_app.command(name="list")
def sources_list_cmd() -> None:
    sources = asyncio.run(_sources_list())
    table = Table(title="kiyooo ingest sources")
    table.add_column("id")
    table.add_column("name")
    table.add_column("system")
    table.add_column("enabled")
    table.add_column("last_sync_at")
    for s in sources:
        table.add_row(str(s.id), s.name, s.system.value, str(s.enabled), str(s.last_sync_at or ""))
    console.print(table)


async def _sources_sync(source_id: uuid.UUID) -> IngestOutcome:
    settings = Settings()
    try:
        org_context = load_org_context(settings.org_context_path)
    except OrgContextError as exc:
        raise typer.BadParameter(f"org-context error: {exc}") from None

    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        source_repo = ExternalFindingSourceRepository(session)
        source = await source_repo.get(source_id)
        if source is None:
            raise typer.BadParameter(f"no ingest source {source_id}")
        outcome = await sync_generic_source(
            source,
            org_context=org_context,
            asset_repo=AssetRepository(session),
            evidence_repo=EvidenceRepository(session),
            finding_repo=FindingRepository(session),
            finding_evidence_repo=FindingEvidenceRepository(session),
            external_finding_repo=ExternalFindingRawRepository(session),
            source_repo=source_repo,
            scan_run_repo=ScanRunRepository(session),
        )
    await engine.dispose()
    return outcome


@sources_app.command(name="sync")
def sources_sync_cmd(
    source_id: str = typer.Option(..., "--id", help="Ingest source id from `sources list`"),
) -> None:
    outcome = asyncio.run(_sources_sync(uuid.UUID(source_id)))
    table = Table(title="kiyooo ingest sources sync")
    table.add_column("metric")
    table.add_column("count")
    table.add_row("mapped", str(outcome.mapped))
    table.add_row("unmapped", str(outcome.unmapped))
    console.print(table)


cloud_app = typer.Typer(
    add_completion=False,
    help="Cloud posture accounts, audited via Prowler (OSS, Apache-2.0) — Stage 13",
)
app.add_typer(cloud_app, name="cloud")

cloud_accounts_app = typer.Typer(add_completion=False, help="AWS/Azure/GCP/Kubernetes accounts")
cloud_app.add_typer(cloud_accounts_app, name="accounts")


async def _cloud_accounts_add(name: str, config: ProwlerConfig) -> uuid.UUID:
    settings = Settings()
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        source = await ExternalFindingSourceRepository(session).create(
            name=name,
            system=ExternalFindingSystem.PROWLER,
            config=config.model_dump(mode="json"),
            enabled=True,
        )
        source_id = source.id
    await engine.dispose()
    return source_id


@cloud_accounts_app.command(name="add")
def cloud_accounts_add_cmd(
    name: str = typer.Option(..., "--name", help="Human label, e.g. 'prod-aws'"),
    config_file: Path = typer.Option(
        ..., "--config", help="YAML/JSON file matching ProwlerConfig's shape"
    ),
) -> None:
    """See `org-context.example/cloud_accounts.yaml` for the shape (provider,
    credential_env, extra_args).
    """
    try:
        raw = yaml.safe_load(config_file.read_text())
        config = ProwlerConfig.model_validate(raw)
    except (yaml.YAMLError, PydanticValidationError, OSError) as exc:
        console.print(f"[red]invalid cloud account config:[/red] {exc}")
        raise typer.Exit(code=1) from None

    account_id = asyncio.run(_cloud_accounts_add(name, config))
    console.print(f"[green]created cloud account[/green] {name!r} — id={account_id}")


@cloud_accounts_app.command(name="list")
def cloud_accounts_list_cmd() -> None:
    sources = asyncio.run(_sources_list())
    table = Table(title="kiyooo cloud accounts")
    table.add_column("id")
    table.add_column("name")
    table.add_column("provider")
    table.add_column("enabled")
    table.add_column("last_sync_at")
    for s in sources:
        if s.system != ExternalFindingSystem.PROWLER:
            continue
        provider = str(s.config.get("provider", ""))
        table.add_row(str(s.id), s.name, provider, str(s.enabled), str(s.last_sync_at or ""))
    console.print(table)


async def _cloud_scan(account_id: uuid.UUID) -> IngestOutcome:
    settings = Settings()
    try:
        org_context = load_org_context(settings.org_context_path)
    except OrgContextError as exc:
        raise typer.BadParameter(f"org-context error: {exc}") from None

    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        source_repo = ExternalFindingSourceRepository(session)
        source = await source_repo.get(account_id)
        if source is None or source.system != ExternalFindingSystem.PROWLER:
            raise typer.BadParameter(f"no cloud account {account_id}")
        outcome = await sync_prowler_source(
            source,
            org_context=org_context,
            asset_repo=AssetRepository(session),
            evidence_repo=EvidenceRepository(session),
            finding_repo=FindingRepository(session),
            finding_evidence_repo=FindingEvidenceRepository(session),
            external_finding_repo=ExternalFindingRawRepository(session),
            source_repo=source_repo,
            scan_run_repo=ScanRunRepository(session),
        )
    await engine.dispose()
    return outcome


@cloud_app.command(name="scan")
def cloud_scan_cmd(
    account_id: str = typer.Option(..., "--account", help="Cloud account id from `accounts list`"),
) -> None:
    outcome = asyncio.run(_cloud_scan(uuid.UUID(account_id)))
    table = Table(title="kiyooo cloud scan")
    table.add_column("metric")
    table.add_column("count")
    table.add_row("mapped", str(outcome.mapped))
    table.add_row("unmapped", str(outcome.unmapped))
    console.print(table)


containers_app = typer.Typer(
    add_completion=False,
    help="Container images / Kubernetes clusters, scanned via Trivy (OSS, Apache-2.0) — "
    "Stage 14",
)
app.add_typer(containers_app, name="containers")

containers_scans_app = typer.Typer(add_completion=False, help="Configured Trivy scans")
containers_app.add_typer(containers_scans_app, name="scans")


async def _containers_scans_add(name: str, config: TrivyConfig) -> uuid.UUID:
    settings = Settings()
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        source = await ExternalFindingSourceRepository(session).create(
            name=name,
            system=ExternalFindingSystem.TRIVY,
            config=config.model_dump(mode="json"),
            enabled=True,
        )
        source_id = source.id
    await engine.dispose()
    return source_id


@containers_scans_app.command(name="add")
def containers_scans_add_cmd(
    name: str = typer.Option(..., "--name", help="Human label, e.g. 'nginx-prod-image'"),
    config_file: Path = typer.Option(
        ..., "--config", help="YAML/JSON file matching TrivyConfig's shape"
    ),
) -> None:
    """See `org-context.example/container_scans.yaml` for the shape
    (scan_kind, target, credential_env, extra_args).
    """
    try:
        raw = yaml.safe_load(config_file.read_text())
        config = TrivyConfig.model_validate(raw)
    except (yaml.YAMLError, PydanticValidationError, OSError) as exc:
        console.print(f"[red]invalid container scan config:[/red] {exc}")
        raise typer.Exit(code=1) from None

    scan_id = asyncio.run(_containers_scans_add(name, config))
    console.print(f"[green]created container scan[/green] {name!r} — id={scan_id}")


@containers_scans_app.command(name="list")
def containers_scans_list_cmd() -> None:
    sources = asyncio.run(_sources_list())
    table = Table(title="kiyooo containers scans")
    table.add_column("id")
    table.add_column("name")
    table.add_column("scan_kind")
    table.add_column("target")
    table.add_column("enabled")
    table.add_column("last_sync_at")
    for s in sources:
        if s.system != ExternalFindingSystem.TRIVY:
            continue
        table.add_row(
            str(s.id),
            s.name,
            str(s.config.get("scan_kind", "")),
            str(s.config.get("target", "")),
            str(s.enabled),
            str(s.last_sync_at or ""),
        )
    console.print(table)


async def _containers_scan(scan_id: uuid.UUID) -> IngestOutcome:
    settings = Settings()
    try:
        org_context = load_org_context(settings.org_context_path)
    except OrgContextError as exc:
        raise typer.BadParameter(f"org-context error: {exc}") from None

    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        source_repo = ExternalFindingSourceRepository(session)
        source = await source_repo.get(scan_id)
        if source is None or source.system != ExternalFindingSystem.TRIVY:
            raise typer.BadParameter(f"no container scan {scan_id}")
        outcome = await sync_trivy_source(
            source,
            org_context=org_context,
            asset_repo=AssetRepository(session),
            evidence_repo=EvidenceRepository(session),
            finding_repo=FindingRepository(session),
            finding_evidence_repo=FindingEvidenceRepository(session),
            external_finding_repo=ExternalFindingRawRepository(session),
            source_repo=source_repo,
            scan_run_repo=ScanRunRepository(session),
        )
    await engine.dispose()
    return outcome


@containers_app.command(name="scan")
def containers_scan_cmd(
    scan_id: str = typer.Option(..., "--id", help="Container scan id from `scans list`"),
) -> None:
    outcome = asyncio.run(_containers_scan(uuid.UUID(scan_id)))
    table = Table(title="kiyooo containers scan")
    table.add_column("metric")
    table.add_column("count")
    table.add_row("mapped", str(outcome.mapped))
    table.add_row("unmapped", str(outcome.unmapped))
    console.print(table)


repos_app = typer.Typer(
    add_completion=False,
    help="Source repos, scanned for verified live secrets via TruffleHog "
    "(OSS engine, AGPL-3.0) — Stage 15",
)
app.add_typer(repos_app, name="repos")

repos_scans_app = typer.Typer(add_completion=False, help="Configured TruffleHog scans")
repos_app.add_typer(repos_scans_app, name="scans")


async def _repos_scans_add(name: str, config: TrufflehogConfig) -> uuid.UUID:
    settings = Settings()
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        source = await ExternalFindingSourceRepository(session).create(
            name=name,
            system=ExternalFindingSystem.TRUFFLEHOG,
            config=config.model_dump(mode="json"),
            enabled=True,
        )
        source_id = source.id
    await engine.dispose()
    return source_id


@repos_scans_app.command(name="add")
def repos_scans_add_cmd(
    name: str = typer.Option(..., "--name", help="Human label, e.g. 'internal-api-repo'"),
    config_file: Path = typer.Option(
        ..., "--config", help="YAML/JSON file matching TrufflehogConfig's shape"
    ),
) -> None:
    """See `org-context.example/repo_scans.yaml` for the shape (repo_url,
    credential_ref, extra_args).
    """
    try:
        raw = yaml.safe_load(config_file.read_text())
        config = TrufflehogConfig.model_validate(raw)
    except (yaml.YAMLError, PydanticValidationError, OSError) as exc:
        console.print(f"[red]invalid repo scan config:[/red] {exc}")
        raise typer.Exit(code=1) from None

    scan_id = asyncio.run(_repos_scans_add(name, config))
    console.print(f"[green]created repo scan[/green] {name!r} — id={scan_id}")


@repos_scans_app.command(name="list")
def repos_scans_list_cmd() -> None:
    sources = asyncio.run(_sources_list())
    table = Table(title="kiyooo repos scans")
    table.add_column("id")
    table.add_column("name")
    table.add_column("repo_url")
    table.add_column("enabled")
    table.add_column("last_sync_at")
    for s in sources:
        if s.system != ExternalFindingSystem.TRUFFLEHOG:
            continue
        table.add_row(
            str(s.id),
            s.name,
            str(s.config.get("repo_url", "")),
            str(s.enabled),
            str(s.last_sync_at or ""),
        )
    console.print(table)


async def _repos_scan(scan_id: uuid.UUID) -> IngestOutcome:
    settings = Settings()
    try:
        org_context = load_org_context(settings.org_context_path)
    except OrgContextError as exc:
        raise typer.BadParameter(f"org-context error: {exc}") from None

    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        source_repo = ExternalFindingSourceRepository(session)
        source = await source_repo.get(scan_id)
        if source is None or source.system != ExternalFindingSystem.TRUFFLEHOG:
            raise typer.BadParameter(f"no repo scan {scan_id}")
        outcome = await sync_trufflehog_source(
            source,
            org_context=org_context,
            asset_repo=AssetRepository(session),
            evidence_repo=EvidenceRepository(session),
            finding_repo=FindingRepository(session),
            finding_evidence_repo=FindingEvidenceRepository(session),
            external_finding_repo=ExternalFindingRawRepository(session),
            source_repo=source_repo,
            scan_run_repo=ScanRunRepository(session),
        )
    await engine.dispose()
    return outcome


@repos_app.command(name="scan")
def repos_scan_cmd(
    scan_id: str = typer.Option(..., "--id", help="Repo scan id from `scans list`"),
) -> None:
    outcome = asyncio.run(_repos_scan(uuid.UUID(scan_id)))
    table = Table(title="kiyooo repos scan")
    table.add_column("metric")
    table.add_column("count")
    table.add_row("mapped", str(outcome.mapped))
    table.add_row("unmapped", str(outcome.unmapped))
    console.print(table)


mobile_app_typer = typer.Typer(
    add_completion=False,
    help="Static analysis of a local APK (apktool + reused TruffleHog filesystem scan) — "
    "Stage 16",
)
app.add_typer(mobile_app_typer, name="mobile")

mobile_scans_app = typer.Typer(add_completion=False, help="Configured mobile scans")
mobile_app_typer.add_typer(mobile_scans_app, name="scans")


async def _mobile_scans_add(name: str, config: MobileScanConfig) -> uuid.UUID:
    settings = Settings()
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        source = await ExternalFindingSourceRepository(session).create(
            name=name,
            system=ExternalFindingSystem.MOBILE_STATIC,
            config=config.model_dump(mode="json"),
            enabled=True,
        )
        source_id = source.id
    await engine.dispose()
    return source_id


@mobile_scans_app.command(name="add")
def mobile_scans_add_cmd(
    name: str = typer.Option(..., "--name", help="Human label, e.g. 'android-app-v2.3'"),
    config_file: Path = typer.Option(
        ..., "--config", help="YAML/JSON file matching MobileScanConfig's shape"
    ),
) -> None:
    """See `org-context.example/mobile_scans.yaml` for the shape
    (platform, apk_path).
    """
    try:
        raw = yaml.safe_load(config_file.read_text())
        config = MobileScanConfig.model_validate(raw)
    except (yaml.YAMLError, PydanticValidationError, OSError) as exc:
        console.print(f"[red]invalid mobile scan config:[/red] {exc}")
        raise typer.Exit(code=1) from None

    scan_id = asyncio.run(_mobile_scans_add(name, config))
    console.print(f"[green]created mobile scan[/green] {name!r} — id={scan_id}")


@mobile_scans_app.command(name="list")
def mobile_scans_list_cmd() -> None:
    sources = asyncio.run(_sources_list())
    table = Table(title="kiyooo mobile scans")
    table.add_column("id")
    table.add_column("name")
    table.add_column("apk_path")
    table.add_column("enabled")
    table.add_column("last_sync_at")
    for s in sources:
        if s.system != ExternalFindingSystem.MOBILE_STATIC:
            continue
        table.add_row(
            str(s.id),
            s.name,
            str(s.config.get("apk_path", "")),
            str(s.enabled),
            str(s.last_sync_at or ""),
        )
    console.print(table)


async def _mobile_scan(scan_id: uuid.UUID) -> IngestOutcome:
    settings = Settings()
    try:
        org_context = load_org_context(settings.org_context_path)
    except OrgContextError as exc:
        raise typer.BadParameter(f"org-context error: {exc}") from None

    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        source_repo = ExternalFindingSourceRepository(session)
        source = await source_repo.get(scan_id)
        if source is None or source.system != ExternalFindingSystem.MOBILE_STATIC:
            raise typer.BadParameter(f"no mobile scan {scan_id}")
        outcome = await sync_mobile_static_source(
            source,
            org_context=org_context,
            asset_repo=AssetRepository(session),
            evidence_repo=EvidenceRepository(session),
            finding_repo=FindingRepository(session),
            finding_evidence_repo=FindingEvidenceRepository(session),
            external_finding_repo=ExternalFindingRawRepository(session),
            source_repo=source_repo,
            scan_run_repo=ScanRunRepository(session),
        )
    await engine.dispose()
    return outcome


@mobile_app_typer.command(name="scan")
def mobile_scan_cmd(
    scan_id: str = typer.Option(..., "--id", help="Mobile scan id from `scans list`"),
) -> None:
    outcome = asyncio.run(_mobile_scan(uuid.UUID(scan_id)))
    table = Table(title="kiyooo mobile scan")
    table.add_column("metric")
    table.add_column("count")
    table.add_row("mapped", str(outcome.mapped))
    table.add_row("unmapped", str(outcome.unmapped))
    console.print(table)


skills_app = typer.Typer(add_completion=False, help="Org-specific playbooks injected into triage")
app.add_typer(skills_app, name="skills")


@skills_app.command(name="list")
def skills_list_cmd() -> None:
    """Loads every org-context/skills/*/SKILL.md — a parse error here is
    the same kind of load-time failure a malformed category gets, not a
    silent skip. See Stage 9.
    """
    settings = Settings()
    try:
        skills = load_skills(settings.org_context_path / "skills")
    except SkillLoadError as exc:
        console.print(f"[red]skill load error:[/red] {exc}")
        raise typer.Exit(code=1) from None

    table = Table(title=f"{len(skills)} skill(s)")
    table.add_column("name")
    table.add_column("description")
    table.add_column("applies_to_categories")
    for skill in skills:
        table.add_row(
            skill.name,
            skill.description,
            ", ".join(skill.applies_to_categories) or "(relevance-matched only)",
        )
    console.print(table)


async def _run_metrics_report(
    settings: Settings, *, analyst_count: int, weeks: float
) -> HealthMetrics:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    async with session_scope(session_factory) as session:
        finding_repo = FindingRepository(session)
        asset_repo = AssetRepository(session)
        ownership_repo = OwnershipRepository(session)
        ticket_repo = TicketRepository(session)
        llm_call_log_repo = LlmCallLogRepository(session)
        scan_run_repo = ScanRunRepository(session)

        findings = await finding_repo.list_all(limit=100_000)
        fixed_findings = [f for f in findings if f.status == FindingStatus.FIXED]
        closure_durations = [
            f.resolved_at - f.first_seen for f in fixed_findings if f.resolved_at is not None
        ]

        assets = await asset_repo.list_all(limit=100_000)
        owner_confidences: list[float] = []
        for asset in assets:
            merged = await merge_existing(asset.id, ownership_repo)
            if merged.top is not None:
                owner_confidences.append(merged.top.confidence)

        retired_count = sum(1 for a in assets if not a.is_active)
        tickets = await ticket_repo.list_all(limit=100_000)
        total_cost = await llm_call_log_repo.total_cost_all_time()
        scan_runs = await scan_run_repo.list_all(limit=100_000)

    await engine.dispose()
    return compute_health_metrics(
        finding_count=len(findings),
        analyst_count=analyst_count,
        weeks=weeks,
        owner_confidences=owner_confidences,
        clarifying_question_count=0,  # no tracking source yet — see docstring
        ticket_count=len(tickets),
        closure_durations=closure_durations,
        decommission_candidates_retired_count=retired_count,
        total_cost_usd=total_cost,
        scan_run_count=len(scan_runs),
    )


metrics_app = typer.Typer(add_completion=False, help="Prometheus + product-health metrics")
app.add_typer(metrics_app, name="metrics")


@metrics_app.command(name="report")
def metrics_report_cmd(
    analysts: int = typer.Option(
        1,
        "--analysts",
        help="Headcount for findings_surfaced_per_analyst_per_week (no user table yet)",
    ),
    weeks: float = typer.Option(1.0, "--weeks", help="Lookback window in weeks"),
) -> None:
    """Product-health metrics — "treat a worsening
    trend as a release blocker, not a dashboard curiosity." Two gaps,
    disclosed rather than faked: clarifying_questions_per_ticket has no
    tracking source yet (always 0 until something logs a "needed a
    follow-up" flag), and decommission_candidates_retired approximates
    with "assets currently inactive" since decommission-candidate status
    isn't persisted historically.
    """
    settings = Settings()
    metrics = asyncio.run(_run_metrics_report(settings, analyst_count=analysts, weeks=weeks))

    table = Table(title="kiyooo metrics report")
    table.add_column("metric")
    table.add_column("value")
    table.add_row(
        "findings_surfaced_per_analyst_per_week",
        f"{metrics.findings_surfaced_per_analyst_per_week:.2f}",
    )
    table.add_row(
        "pct_assets_with_owner_confidence_gte_0.8",
        f"{metrics.pct_assets_with_owner_confidence_gte_0_8:.0%}",
    )
    table.add_row(
        "clarifying_questions_per_ticket", f"{metrics.clarifying_questions_per_ticket:.2f}"
    )
    table.add_row(
        "median_time_to_verified_closure", str(metrics.median_time_to_verified_closure or "n/a")
    )
    table.add_row("decommission_candidates_retired", str(metrics.decommission_candidates_retired))
    table.add_row("cost_per_scan_run (USD)", f"${metrics.cost_per_scan_run:.4f}")
    console.print(table)


async def _run_audit_export(settings: Settings, since_hours: int) -> list[AuditLog]:
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    cutoff = datetime.now(UTC) - timedelta(hours=since_hours)
    async with session_scope(session_factory) as session:
        rows = await AuditLogRepository(session).since(cutoff)
    await engine.dispose()
    return rows


audit_app = typer.Typer(add_completion=False, help="ScopeGuard audit log export")
app.add_typer(audit_app, name="audit")


@audit_app.command(name="export")
def audit_export_cmd(
    output: Path = typer.Option(..., "--output", help="Destination JSON file"),
    hours: int = typer.Option(24 * 7, "--hours", help="Lookback window"),
) -> None:
    """Dumps ScopeGuard's append-only audit_log to JSON — the design Stage
    11's audit log export. Every row is a decision (ALLOW/DENY/REQUIRES_
    CONFIRM) invariant #2 already required to exist; this just makes it
    portable for a SIEM or compliance review outside this database.
    """
    settings = Settings()
    rows = asyncio.run(_run_audit_export(settings, hours))
    payload = [
        {
            "id": str(row.id),
            "scan_run_id": str(row.scan_run_id) if row.scan_run_id else None,
            "finding_id": str(row.finding_id) if row.finding_id else None,
            "tool": row.tool,
            "target": row.target,
            "is_active": row.is_active,
            "decision": row.decision.value,
            "reason": row.reason,
            "occurred_at": row.occurred_at.isoformat(),
        }
        for row in rows
    ]
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    console.print(f"[green]exported {len(rows)} audit_log row(s)[/green] to {output}")


@app.command()
def serve(
    host: str | None = typer.Option(None, "--host", help="Defaults to settings.api_host"),
    port: int | None = typer.Option(None, "--port", help="Defaults to settings.api_port"),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on source changes (dev only)"),
) -> None:
    """Runs the FastAPI backend — assets, findings,
    change feed, scan runs, review actions, ownership override, coverage
    stats. No auth: see kiyooo/api/deps.py. Serves the Next.js UI's API
    calls; OpenAPI spec is at /openapi.json once running.
    """
    import uvicorn

    settings = Settings()
    uvicorn.run(
        "kiyooo.api.app:app",
        host=host or settings.api_host,
        port=port or settings.api_port,
        reload=reload,
    )


if __name__ == "__main__":
    app()
