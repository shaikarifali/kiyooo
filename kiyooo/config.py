"""Runtime settings (env) and the org-context loader.

Org-context is the customization surface: `scope.yaml`, `teams.yaml`,
`controls.yaml`, `categories/**/*.yaml`, all git-owned by the org, not this repo.
The one rule that matters here: a malformed category is a hard failure at load time,
never a silent skip. Predicate *evaluation* (what `hostname_matches` actually does at
scan time) is Stage 4 — this module only validates shape: required fields, types,
enum values, regex syntax, and category-id uniqueness.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# --------------------------------------------------------------------------- #
# Process settings — env-sourced, not org-context.
# --------------------------------------------------------------------------- #


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KIYOOO_", env_file=".env", extra="ignore")

    environment: Literal["dev", "staging", "prod"] = "dev"
    log_level: str = "INFO"

    database_url: str = "postgresql+asyncpg://kiyooo:kiyooo@localhost:5432/kiyooo"
    redis_url: str = "redis://localhost:6379/0"

    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "kiyooo"
    minio_secret_key: str = "kiyooo-dev-only"
    minio_bucket: str = "kiyooo-evidence"
    minio_secure: bool = False

    # Bulk pass — the 90% case. Defaults
    # to local: zero marginal cost, nothing leaves the host. See §11 open
    # question #1 — this is deliberately the config knob that answers it.
    llm_provider: str = "ollama"
    llm_base_url: str = "http://localhost:11434"
    bulk_model: str = "llama3.1:8b"

    # Escalation pass — frontier model, only called when the bulk pass is
    # under-confident, severity >= high, or the category is always_escalate.
    escalation_provider: str = "anthropic"
    escalation_model: str = "claude-sonnet-5"
    anthropic_api_key: str | None = None
    openai_api_key: str | None = None
    openrouter_api_key: str | None = None

    # Stage 1b vendor ingest credentials.
    mandiant_api_key: str | None = None
    tenable_access_key: str | None = None
    tenable_secret_key: str | None = None

    # Stage 7 routing sink credentials. webhook_url is the generic-webhook
    # sink's target; slack_webhook_url is a Slack incoming-webhook URL used
    # for both per-finding notify and the daily digest.
    webhook_url: str | None = None
    slack_webhook_url: str | None = None
    github_token: str | None = None
    github_repo: str | None = None  # "owner/repo" — Stage 7's Issues sink
    # Stage 8's feedback/promote.py opens its suppression PR against this
    # repo instead — org-context is a separate git repo the org owns
    #, never this one.
    org_context_repo: str | None = None  # "owner/repo"

    embedding_provider: str = "ollama"
    embedding_model: str = "nomic-embed-text"

    # Hard per-scan-run ceiling — a run that would
    # exceed this halts and reports rather than silently burning budget.
    max_cost_usd_per_run: float = 5.0

    org_context_path: Path = Path("./org-context.example")
    # Where `kiyooo review` auto-adds newly labeled findings (the design
    # Stage 8's "auto-add reviewed findings to the eval corpus"). Defaults
    # to this repo's own illustrative corpus so it works out of the box;
    # point it at your org's real corpus once you have one.
    eval_corpus_path: Path = Path("./tests/eval/corpus")
    # Stage 11's daily `refresh_kev_feed` worker task writes CISA's raw KEV
    # JSON here; scheduled detect runs read it back instead of hitting the
    # feed on every single scan.
    kev_cache_path: Path = Path("./.cache/kev.json")
    # Stage 11: if set, `scan`/`triage` write a Prometheus textfile-
    # collector-format file here at the end of every run
    # ("cost_per_scan_run printed at the end of every run"). Unset by
    # default — most single-user CLI runs don't need it.
    metrics_textfile_path: Path | None = None

    # Stage 10: FastAPI serving config. No auth yet — see kiyooo/api/deps.py.
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])


# --------------------------------------------------------------------------- #
# Predicate expression shape (Stage 4 gives these meaning; Stage 0 only validates
# that the shape and any embedded regex are well-formed).
# --------------------------------------------------------------------------- #

_REGEX_PREDICATE_KEYS = {
    "hostname_matches",
    "tls_cert_cn_matches",
    "http_body_matches",
    "redirect_chain_matches",
}

PredicateClause = dict[str, object]


def _validate_predicate_clauses(
    clauses: list[PredicateClause], *, where: str
) -> list[PredicateClause]:
    for clause in clauses:
        if len(clause) != 1:
            raise ValueError(
                f"{where}: each predicate clause must have exactly one key, got {clause!r}"
            )
        ((key, value),) = clause.items()
        if key in _REGEX_PREDICATE_KEYS:
            if not isinstance(value, str):
                raise ValueError(f"{where}: {key} expects a string regex, got {value!r}")
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"{where}: {key} has invalid regex {value!r}: {exc}") from exc
        elif key == "http_header_matches":
            if not isinstance(value, dict):
                raise ValueError(f"{where}: http_header_matches expects a mapping, got {value!r}")
            for header_name, pattern in value.items():
                try:
                    re.compile(str(pattern))
                except re.error as exc:
                    raise ValueError(
                        f"{where}: http_header_matches[{header_name!r}] invalid regex: {exc}"
                    ) from exc
    return clauses


class PredicateBlock(BaseModel):
    model_config = ConfigDict(extra="forbid")

    all_of: list[PredicateClause] = Field(default_factory=list)
    any_of: list[PredicateClause] = Field(default_factory=list)

    @model_validator(mode="after")
    def _at_least_one_clause(self) -> PredicateBlock:
        if not self.all_of and not self.any_of:
            raise ValueError("detect/suppress_if block must have at least one of all_of/any_of")
        _validate_predicate_clauses(self.all_of, where="all_of")
        _validate_predicate_clauses(self.any_of, where="any_of")
        return self


# --------------------------------------------------------------------------- #
# categories/*.yaml — the design
# --------------------------------------------------------------------------- #

Severity = Literal["critical", "high", "medium", "low", "info"]
AssetTypeName = Literal[
    "domain",
    "subdomain",
    "ip",
    "url",
    "http_service",
    "tcp_service",
    "cloud_resource",
    "repo",
    "cert",
    "asn",
    "netblock",
    "saas_tenant",
    "mobile_app",
    "llm_endpoint",
    "vector_db",
    "mcp_server",
    "model_registry",
    "ai_agent_webhook",
    "notebook",
    "ai_app",
    "ai_saas_tenant",
    "container_image",
    "k8s_cluster",
    "k8s_workload",
]

# the design open question #2: some orgs cannot send response bodies to a
# hosted API. A category declares the minimum profile it's triageable
# under; `triage/bundler.py` enforces it before any hosted-provider call.
#   full          - everything: bodies, headers, evidence content_inline as-is.
#   headers_only  - headers/metadata only; response/cert bodies redacted.
#   local_only    - never sent to a hosted provider at all; local-model-only.
RedactionProfile = Literal["full", "headers_only", "local_only"]


class RouteConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assign_to: str
    cc: list[str] = Field(default_factory=list)
    notify_channels: list[str] = Field(default_factory=list)
    sla_days: dict[Severity, int]
    ticket_template: str | None = None
    # Stage 7's autonomy ladder: 0=shadow (nothing sent), 1=every
    # outbound drafted and held for a human to click send, 2=low/medium
    # auto-file but high/critical still held, 3=everything auto-files.
    # Stored per category, in org-context, so promoting one is a reviewable
    # diff — never a runtime decision. Every new category ships at 0.
    autonomy_level: Literal[0, 1, 2, 3] = 0


class CategoryDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    version: int = Field(ge=1)
    enabled: bool = True
    severity_base: Severity
    applies_to: list[AssetTypeName] = Field(min_length=1)

    detect: PredicateBlock
    suppress_if: list[PredicateClause] = Field(default_factory=list)
    evidence_required: list[str] = Field(default_factory=list)

    # Stage 17 — the attack-path engine's endpoint marker.
    # "Extend the existing category schema, don't invent a parallel one":
    # a finding in a category with this set to true means its asset holds
    # or grants access to something worth protecting (data, credentials) —
    # `graph/attack_path.py` looks for paths connecting an unrelated
    # weakness to one of these, not a separate sensitivity config file.
    is_sensitive_target: bool = False

    triage_hints: str = Field(min_length=1)

    always_escalate: bool = False
    escalation_threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    redaction_profile: RedactionProfile = "full"

    # `ingest/pipeline.py::ingest_finding`'s fingerprint discriminator for
    # vendor-sourced findings. "one_per_asset" (the default, and every
    # category's behavior before this field existed) is what makes
    # cross-tool reconciliation work — three vendors reporting the same
    # category on the same asset collapse to one Finding, regardless of
    # their different external_ids (see
    # tests/ingest/test_pipeline.py::test_cross_tool_reconciliation_
    # collapses_to_one_finding). "one_per_vendor_finding" is for categories
    # that are deliberately a *bucket* of many genuinely distinct issues
    # sharing one category+asset — Stage 14's `vulnerable-base-image` (many
    # CVEs per image), Stage 15/16's leaked-secret categories (many secrets
    # per repo/app) — where collapsing would silently merge unrelated
    # problems' titles into one. Caught live: two different verified
    # secrets in one repo produced one Finding until this existed.
    finding_granularity: Literal["one_per_asset", "one_per_vendor_finding"] = "one_per_asset"

    route: RouteConfig

    source_file: str = Field(default="", exclude=True)

    @field_validator("id")
    @classmethod
    def _id_is_slug(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", value):
            raise ValueError(f"category id must be a lowercase, hyphenated slug, got {value!r}")
        return value


# --------------------------------------------------------------------------- #
# scope.yaml
# --------------------------------------------------------------------------- #


class ScopeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    org_name: str
    relationship: Literal["first_party", "third_party"] = "first_party"
    active_scanning_enabled: bool = False
    authorized_by: str | None = None
    authorization_date: str | None = None
    attestation: bool = False

    domains: list[str] = Field(default_factory=list)
    wildcards: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    asns: list[int] = Field(default_factory=list)
    cloud_accounts: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _third_party_is_always_passive(self) -> ScopeConfig:
        if self.relationship == "third_party" and self.active_scanning_enabled:
            raise ValueError(
                "scope.yaml: active_scanning_enabled cannot be true when relationship is "
                "third_party — outward mode is passive-only, structurally, not by policy"
            )
        return self

    @model_validator(mode="after")
    def _active_scanning_requires_attestation(self) -> ScopeConfig:
        if self.active_scanning_enabled and not self.attestation:
            raise ValueError(
                "scope.yaml: active_scanning_enabled=true requires attestation=true plus "
                "authorized_by and authorization_date"
            )
        return self


# --------------------------------------------------------------------------- #
# teams.yaml — the design
# --------------------------------------------------------------------------- #


class TeamOwnership(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cloud_accounts: list[str] = Field(default_factory=list)
    dns_patterns: list[str] = Field(default_factory=list)
    repos: list[str] = Field(default_factory=list)
    cloud_tags: dict[str, str] = Field(default_factory=dict)


class TeamDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    slack: str | None = None
    manager: EmailStr
    members: list[EmailStr] = Field(default_factory=list)
    owns: TeamOwnership = Field(default_factory=TeamOwnership)
    escalation_after_sla: EmailStr | None = None
    ticket_system: Literal["jira", "linear", "github", "servicenow"] | None = None
    jira_project: str | None = None


class TeamsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    teams: list[TeamDefinition] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_ids(self) -> TeamsFile:
        ids = [t.id for t in self.teams]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"teams.yaml: duplicate team id(s): {sorted(dupes)}")
        return self


# --------------------------------------------------------------------------- #
# controls.yaml — the design
# --------------------------------------------------------------------------- #


class ControlDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    detect: PredicateBlock
    mitigates: list[str] = Field(min_length=1)
    action: Literal["reduce_severity", "suppress"]
    reduce_by: int | None = None
    never_applies_to: list[str] = Field(default_factory=list)
    requires_human_confirm_once: bool = False
    note: str | None = None

    @model_validator(mode="after")
    def _reduce_severity_needs_amount(self) -> ControlDefinition:
        if self.action == "reduce_severity" and self.reduce_by is None:
            raise ValueError(f"control {self.id!r}: action=reduce_severity requires reduce_by")
        return self


def _default_never_suppress() -> list[Severity]:
    return ["critical"]


class ControlsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    controls: list[ControlDefinition] = Field(default_factory=list)
    never_suppress_severities: list[Severity] = Field(default_factory=_default_never_suppress)

    @model_validator(mode="after")
    def _unique_ids(self) -> ControlsFile:
        ids = [c.id for c in self.controls]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"controls.yaml: duplicate control id(s): {sorted(dupes)}")
        return self


# --------------------------------------------------------------------------- #
# ownership_overrides.yaml — Stage 3, the `manual` ownership source
# (confidence 1.00). The only ownership source that isn't inferred from
# something else — an admin states the answer directly, so it always wins.
# --------------------------------------------------------------------------- #


class OwnershipOverride(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_value: str
    owner_type: Literal["user", "team"]
    owner_ref: str
    note: str | None = None


class OwnershipOverridesFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    overrides: list[OwnershipOverride] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_asset_values(self) -> OwnershipOverridesFile:
        values = [o.asset_value for o in self.overrides]
        dupes = {v for v in values if values.count(v) > 1}
        if dupes:
            raise ValueError(f"ownership_overrides.yaml: duplicate asset_value(s): {sorted(dupes)}")
        return self


# --------------------------------------------------------------------------- #
# vendor_mapping.yaml — Stage 1b: vendor_issue_type -> our
# category_id, PR-reviewed so a mapping change is a reviewable diff, not a
# runtime decision.
# --------------------------------------------------------------------------- #


class VendorMappingEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vendor_issue_type: str
    category_id: str


class VendorMappingFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mappings: list[VendorMappingEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_vendor_issue_types(self) -> VendorMappingFile:
        types = [m.vendor_issue_type for m in self.mappings]
        dupes = {t for t in types if types.count(t) > 1}
        if dupes:
            raise ValueError(
                f"vendor_mapping.yaml: duplicate vendor_issue_type(s): {sorted(dupes)}"
            )
        return self


# --------------------------------------------------------------------------- #
# suppressions.yaml — Stage 8's `feedback/promote.py` output: when
# N humans mark the same category+asset a false positive for the same
# reason, a PR proposes an entry here rather than eating that noise forever.
# Deliberately not predicate-based like `suppress_if`/`controls.yaml` — a
# free-text human rationale can't be turned into a precise predicate without
# another model call, which invariant #4 forbids for a suppression decision.
# A literal (category_id, asset_value) match is exact, auditable, and diffable.
# --------------------------------------------------------------------------- #


class SuppressionEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    category_id: str
    asset_values: list[str] = Field(min_length=1)
    reason: str
    promoted_from_review_ids: list[str] = Field(default_factory=list)


class SuppressionsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    suppressions: list[SuppressionEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_ids(self) -> SuppressionsFile:
        ids = [s.id for s in self.suppressions]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"suppressions.yaml: duplicate id(s): {sorted(dupes)}")
        return self


# --------------------------------------------------------------------------- #
# Aggregate + loader
# --------------------------------------------------------------------------- #


class OrgContextError(Exception):
    """Raised for any malformed org-context file. Never swallowed, never partial-loaded."""


class OrgContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: ScopeConfig
    teams: TeamsFile
    controls: ControlsFile
    categories: dict[str, CategoryDefinition]
    ownership_overrides: OwnershipOverridesFile
    vendor_mapping: VendorMappingFile = Field(default_factory=VendorMappingFile)
    suppressions: SuppressionsFile = Field(default_factory=SuppressionsFile)


def _read_yaml(path: Path) -> object:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise OrgContextError(f"{path}: invalid YAML: {exc}") from exc
    except OSError as exc:
        raise OrgContextError(f"{path}: could not read file: {exc}") from exc


def load_org_context(root: Path) -> OrgContext:
    """Parse and validate the full org-context tree rooted at `root`.

    Any single malformed file — bad YAML, missing required field, wrong type, bad
    regex, duplicate category id — aborts the whole load with an `OrgContextError`
    naming the offending file. There is no partial/best-effort mode: a category the
    loader can't validate is a category that must never silently fail to fire.
    """
    scope_path = root / "scope.yaml"
    teams_path = root / "teams.yaml"
    controls_path = root / "controls.yaml"
    ownership_overrides_path = root / "ownership_overrides.yaml"
    vendor_mapping_path = root / "vendor_mapping.yaml"
    suppressions_path = root / "suppressions.yaml"
    categories_dir = root / "categories"

    if not root.is_dir():
        raise OrgContextError(f"org-context root does not exist or is not a directory: {root}")

    try:
        scope = ScopeConfig.model_validate(_read_yaml(scope_path))
    except Exception as exc:
        raise OrgContextError(f"{scope_path}: {exc}") from exc

    try:
        teams_raw = _read_yaml(teams_path) if teams_path.exists() else {"teams": []}
        teams = TeamsFile.model_validate(teams_raw)
    except Exception as exc:
        raise OrgContextError(f"{teams_path}: {exc}") from exc

    try:
        controls_raw = _read_yaml(controls_path) if controls_path.exists() else {"controls": []}
        controls = ControlsFile.model_validate(controls_raw)
    except Exception as exc:
        raise OrgContextError(f"{controls_path}: {exc}") from exc

    try:
        overrides_raw = (
            _read_yaml(ownership_overrides_path)
            if ownership_overrides_path.exists()
            else {"overrides": []}
        )
        ownership_overrides = OwnershipOverridesFile.model_validate(overrides_raw)
    except Exception as exc:
        raise OrgContextError(f"{ownership_overrides_path}: {exc}") from exc

    try:
        vendor_mapping_raw = (
            _read_yaml(vendor_mapping_path) if vendor_mapping_path.exists() else {"mappings": []}
        )
        vendor_mapping = VendorMappingFile.model_validate(vendor_mapping_raw)
    except Exception as exc:
        raise OrgContextError(f"{vendor_mapping_path}: {exc}") from exc

    try:
        suppressions_raw = (
            _read_yaml(suppressions_path) if suppressions_path.exists() else {"suppressions": []}
        )
        suppressions = SuppressionsFile.model_validate(suppressions_raw)
    except Exception as exc:
        raise OrgContextError(f"{suppressions_path}: {exc}") from exc

    categories: dict[str, CategoryDefinition] = {}
    if categories_dir.is_dir():
        # `*.cases.yaml` is Stage 4's `categories test` fixture format
        # (`detect/cases.py`) — a category YAML's should-match/should-not-
        # match sibling, not a category itself.
        category_files = (
            f for f in sorted(categories_dir.rglob("*.yaml")) if not f.name.endswith(".cases.yaml")
        )
        for category_file in category_files:
            raw = _read_yaml(category_file)
            try:
                category = CategoryDefinition.model_validate(raw)
            except Exception as exc:
                raise OrgContextError(f"{category_file}: malformed category: {exc}") from exc
            if category.id in categories:
                raise OrgContextError(
                    f"{category_file}: duplicate category id {category.id!r}, "
                    f"already defined in {categories[category.id].source_file}"
                )
            category.source_file = str(category_file)
            categories[category.id] = category

    return OrgContext(
        scope=scope,
        teams=teams,
        controls=controls,
        categories=categories,
        ownership_overrides=ownership_overrides,
        vendor_mapping=vendor_mapping,
        suppressions=suppressions,
    )
