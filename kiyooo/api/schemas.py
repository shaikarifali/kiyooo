"""API response/request schemas — the boundary types
CLAUDE.md requires for anything crossing the API surface. Deliberately
separate from `db/models.py`'s SQLAlchemy models: a response shape is a
public contract, an ORM column list is an implementation detail, and the
two should be free to diverge (e.g. a Verdict response never includes
`input_hash`, an internal cache key with no meaning to a triager).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from kiyooo.db.models import (
    AssetType,
    ChangeEventKind,
    EvidenceKind,
    ExclusionSource,
    ExternalFindingSystem,
    FindingDetector,
    FindingStatus,
    IdentifierAuthority,
    IdentifierKind,
    IdentifierSource,
    IdentifierStatus,
    ModelPinRole,
    OrgRelationship,
    OwnerType,
    ScanRunStatus,
    ScanTrigger,
    ScopeAction,
    SeedKind,
    Severity,
    VerdictValue,
)
from kiyooo.ingest.adapters.generic_rest import GenericRestConfig
from kiyooo.ingest.adapters.mobile_static import MobileScanConfig
from kiyooo.ingest.adapters.prowler import ProwlerConfig
from kiyooo.ingest.adapters.trivy import TrivyConfig
from kiyooo.ingest.adapters.trufflehog import TrufflehogConfig


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    type: AssetType
    value: str
    first_seen: datetime
    last_seen: datetime
    is_active: bool
    confidence_in_scope: float
    scope_reason: str | None
    attributes: dict[str, object]


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    kind: EvidenceKind
    source_tool: str
    collected_at: datetime
    content_inline: dict[str, object] | None
    redacted: bool
    injection_suspected: bool


class VerdictOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    model: str
    prompt_version: str
    verdict: VerdictValue
    confidence: float
    adjusted_severity: Severity
    reasoning: str
    business_impact_hypothesis: str
    citations: list[str]
    compensating_controls: list[str]
    exploitability: dict[str, object] | None
    remediation: dict[str, object] | None
    cost_usd: float
    created_at: datetime


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_run_id: UUID
    asset_id: UUID
    category_id: str
    raw_severity: Severity
    title: str
    description: str | None
    detector: FindingDetector
    status: FindingStatus
    first_seen: datetime
    last_seen: datetime
    resolved_at: datetime | None


class IdentifierVerificationOut(BaseModel):
    """One claim the model made (a CVE, CWE, package version, hostname...)
    and what checking it against an authoritative source (NVD/KEV/OSV/DNS/
    the evidence bundle itself) actually found — invariant #4's audit
    trail, made visible: a triager should never have to take a cited
    identifier on faith. `status: hallucinated` is the case that matters
    most — a claim the validator could not verify anywhere.
    """

    model_config = ConfigDict(from_attributes=True)

    kind: IdentifierKind
    claimed_value: str
    source: IdentifierSource
    resolved: bool
    authority: IdentifierAuthority | None
    resolved_value: str | None
    status: IdentifierStatus
    checked_at: datetime


class HumanReviewOut(BaseModel):
    """One past human decision on this finding — invariant #4/#6's audit
    trail that a person, not the model, actually closed the loop. Distinct
    from `ReviewOut` (the immediate response to submitting one), this is
    the full row for a finding-detail page's decision history.
    """

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    reviewer: str
    agreed_with_model: bool
    final_verdict: VerdictValue
    rationale: str
    created_at: datetime


class FindingDetailOut(BaseModel):
    """`GET /api/findings/{id}` — the finding plus everything a triager
    needs to decide without leaving the page (the design's "finding + verdict
    + reasoning + evidence + agree/disagree" triage-queue deliverable).
    """

    model_config = ConfigDict(from_attributes=True)

    finding: FindingOut
    asset: AssetOut
    latest_verdict: VerdictOut | None
    evidence: list[EvidenceOut]
    identifier_verifications: list[IdentifierVerificationOut]
    human_reviews: list[HumanReviewOut]


class ChangeEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_run_id: UUID
    asset_id: UUID
    kind: ChangeEventKind
    before: dict[str, object] | None
    after: dict[str, object] | None
    severity_hint: Severity | None
    occurred_at: datetime


class ScanRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    started_at: datetime
    finished_at: datetime | None
    status: ScanRunStatus
    trigger: ScanTrigger


class AssetEdgeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    src_asset_id: UUID
    dst_asset_id: UUID
    relation: str
    confidence: float
    discovered_by: str


class OwnershipOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    owner_type: OwnerType
    owner_ref: str
    source: str
    confidence: float
    note: str | None = None


class TeamSummaryOut(BaseModel):
    """`GET /api/teams` — backs the web UI's assign-owner picker
    (`teams.yaml` §5.3). `members` doubles as the "Users" tab's search
    pool; there's no separate user directory in this project, so an
    individual is whoever's listed as a member of at least one team.
    """

    id: str
    slack: str | None
    manager: str
    members: list[str]


class CoverageStatsOut(BaseModel):
    total_assets: int
    active_assets: int
    resolved_ownership: int
    disputed_ownership: int
    orphan_ownership: int
    pct_owner_confidence_gte_0_8: float


class ReviewRequest(BaseModel):
    verdict: VerdictValue
    rationale: str = Field(min_length=1)
    reviewer: str = Field(min_length=1)


class ReviewOut(BaseModel):
    finding_id: UUID
    agreed_with_model: bool
    final_verdict: VerdictValue


class OwnershipOverrideRequest(BaseModel):
    owner_type: OwnerType
    owner_ref: str = Field(min_length=1)
    note: str | None = None
    reviewer: str = Field(min_length=1)


# --------------------------------------------------------------------------- #
# kiyooo-easm-standalone.md Part D §1 (build item 1): org + seed + exclusion.
# UI/CLI parity (Part D §8: "the UI is a client of the same API the CLI
# uses") — these mirror kiyooo/cli.py's org/seed/exclusion commands exactly,
# same repository calls underneath.
# --------------------------------------------------------------------------- #


class OrganizationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
    parent_org_id: UUID | None
    relationship: OrgRelationship
    legal_entity_name: str | None
    country: str | None
    active_scanning_allowed: bool
    authorization_id: str | None
    created_at: datetime
    created_by: str


class OrganizationCreateRequest(BaseModel):
    slug: str = Field(min_length=1)
    name: str = Field(min_length=1)
    parent_org_id: UUID | None = None
    relationship: OrgRelationship = OrgRelationship.SELF
    legal_entity_name: str | None = None
    country: str | None = None
    active_scanning_allowed: bool = False
    authorization_id: str | None = None
    created_by: str = Field(min_length=1)


class SeedOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    org_id: UUID
    kind: SeedKind
    value: str
    scope_action: ScopeAction
    active_scan_allowed: bool | None
    verified: bool
    note: str | None
    added_by: str
    added_at: datetime
    disabled_at: datetime | None


class SeedCreateRequest(BaseModel):
    org_id: UUID
    kind: SeedKind
    value: str = Field(min_length=1)
    scope_action: ScopeAction = ScopeAction.INCLUDE
    active_scan_allowed: bool | None = None
    note: str | None = None
    added_by: str = Field(min_length=1)


class ExclusionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    org_id: UUID | None
    kind: SeedKind
    value: str
    reason: str
    source: ExclusionSource
    created_at: datetime


class ExclusionCreateRequest(BaseModel):
    org_id: UUID | None = None
    kind: SeedKind
    value: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    source: ExclusionSource = ExclusionSource.USER


# --------------------------------------------------------------------------- #
# Model configuration — which provider/model runs bulk/escalation/embedding.
# Mirrors `kiyooo providers list/pin/test` exactly (Part D §8 parity rule).
# No credential field anywhere here: invariant #6/#7 — a key is never
# accepted from a request body or stored in the DB, only read from
# `Settings`/env at test-connection time.
# --------------------------------------------------------------------------- #


class ModelPinOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    role: ModelPinRole
    provider: str
    model: str
    digest: str
    endpoint_url: str | None
    credential_ref: str | None
    pinned_at: datetime
    pinned_by: str
    eval_run_id: str | None
    changelog_note: str


class ModelPinCreateRequest(BaseModel):
    role: ModelPinRole
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    digest: str = Field(min_length=1)
    pinned_by: str = Field(min_length=1)
    changelog_note: str = Field(min_length=1)
    endpoint_url: str | None = None
    credential_ref: str | None = None
    eval_run_id: str | None = None


class RoleDefaultOut(BaseModel):
    """What a role falls back to when nothing's pinned — read straight
    from `Settings`, so the UI can show "settings (unpinned)" next to the
    same value `select_model` would actually use.
    """

    role: ModelPinRole
    provider: str
    model: str


class ModuleToggleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    module_key: str
    enabled: bool
    updated_at: datetime


class ModuleToggleUpdateRequest(BaseModel):
    enabled: bool


class ProviderTestRequest(BaseModel):
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    endpoint_url: str | None = None
    credential_ref: str | None = None


class ProviderTestResultOut(BaseModel):
    ok: bool
    latency_ms: int
    detail: str
    model_found: bool | None


# --------------------------------------------------------------------------- #
# External finding ingest — "point kiyooo at the
# ASM/VM tool(s) an org already pays for." `IngestSourceCreateRequest`
# embeds `GenericRestConfig` directly so its own field validation (auth
# type needs credential_ref, etc.) runs at the API boundary, not just in
# the CLI. `system` is always CUSTOM here — the two hand-written adapters
# (Mandiant/Tenable) are configured via `Settings`/env, not this endpoint.
# --------------------------------------------------------------------------- #


class IngestSourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    system: ExternalFindingSystem
    config: dict[str, object]
    enabled: bool
    last_sync_at: datetime | None
    last_cursor: str | None


class IngestSourceCreateRequest(BaseModel):
    name: str = Field(min_length=1)
    config: GenericRestConfig
    enabled: bool = True


class IngestSourceUpdateRequest(BaseModel):
    name: str = Field(min_length=1)
    config: GenericRestConfig
    enabled: bool = True


class IngestSyncResultOut(BaseModel):
    mapped: int
    unmapped: int


class UnmappedFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    source_id: UUID
    source_name: str
    external_id: str
    mapping_notes: str | None
    ingested_at: datetime


class IngestTestResultOut(BaseModel):
    """A dry run — fetches and parses like a real sync, previews how many
    items would map vs. not, but never writes to the DB. Lets a source get
    tried out before it's saved, same as the model-config page's "Test
    before pinning".
    """

    ok: bool
    item_count: int
    mapped_preview: int
    unmapped_preview: int
    sample_titles: list[str]
    error: str | None


# --------------------------------------------------------------------------- #
# Cloud posture — Prowler-backed accounts. Own
# endpoints rather than reusing `/api/ingest/sources`: a `ProwlerConfig`
# (provider + credential env-var map) has no `base_url`/field-mapping shape
# in common with `GenericRestConfig`, and syncing one always means "run a
# full audit," never an incremental fetch — different enough to deserve its
# own small surface, same underlying `ExternalFindingSource` table.
# --------------------------------------------------------------------------- #


class CloudAccountOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    config: dict[str, object]
    enabled: bool
    last_sync_at: datetime | None


class CloudAccountCreateRequest(BaseModel):
    name: str = Field(min_length=1)
    config: ProwlerConfig
    enabled: bool = True


class CloudAccountUpdateRequest(BaseModel):
    name: str = Field(min_length=1)
    config: ProwlerConfig
    enabled: bool = True


# --------------------------------------------------------------------------- #
# Containers & Kubernetes — Trivy-backed scans. Own
# endpoints for the same reason `/api/cloud/accounts` has its own: a
# `TrivyConfig` has no shape in common with `GenericRestConfig`, and a scan
# always means "run Trivy now," never an incremental fetch.
# --------------------------------------------------------------------------- #


class ContainerScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    config: dict[str, object]
    enabled: bool
    last_sync_at: datetime | None


class ContainerScanCreateRequest(BaseModel):
    name: str = Field(min_length=1)
    config: TrivyConfig
    enabled: bool = True


class ContainerScanUpdateRequest(BaseModel):
    name: str = Field(min_length=1)
    config: TrivyConfig
    enabled: bool = True


# --------------------------------------------------------------------------- #
# Source code & supply chain — TruffleHog-backed repo
# scans. Own endpoints, same reasoning as `/api/cloud/accounts` and
# `/api/containers/scans`: `TrufflehogConfig` has its own shape and a scan
# always means "run TruffleHog now."
# --------------------------------------------------------------------------- #


class RepoScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    config: dict[str, object]
    enabled: bool
    last_sync_at: datetime | None


class RepoScanCreateRequest(BaseModel):
    name: str = Field(min_length=1)
    config: TrufflehogConfig
    enabled: bool = True


class RepoScanUpdateRequest(BaseModel):
    name: str = Field(min_length=1)
    config: TrufflehogConfig
    enabled: bool = True


# --------------------------------------------------------------------------- #
# Mobile static analysis — apktool + reused TruffleHog
# filesystem scan, Android only. Own endpoints, same reasoning as the other
# domain-expansion stages.
# --------------------------------------------------------------------------- #


class MobileScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    config: dict[str, object]
    enabled: bool
    last_sync_at: datetime | None


class MobileScanCreateRequest(BaseModel):
    name: str = Field(min_length=1)
    config: MobileScanConfig
    enabled: bool = True


class MobileScanUpdateRequest(BaseModel):
    name: str = Field(min_length=1)
    config: MobileScanConfig
    enabled: bool = True


# --------------------------------------------------------------------------- #
# Attack path engine — computed on demand from the
# current asset graph + finding state, not a persisted table. See
# `graph/attack_path.py`'s module docstring for why.
# --------------------------------------------------------------------------- #


class AttackPathHopOut(BaseModel):
    asset_id: UUID
    asset_type: str
    asset_value: str
    finding_id: UUID | None
    finding_category_id: str | None
    finding_severity: str | None


class AttackPathOut(BaseModel):
    hops: list[AttackPathHopOut]
    score: float
    sensitive_category_id: str
