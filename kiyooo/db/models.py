"""SQLAlchemy 2.0 models — the schema in the design, implemented as specified.

Deliberately no ORM `relationship()` graph here: every cross-table reference is a
plain foreign-key column. The repository layer (`db/repo/`) does explicit queries.
This keeps Stage 0 to what the plan asks for and avoids committing to a relationship
shape before Stage 2's graph builder exists.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    ARRAY,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import Enum as SAEnum

# nomic-embed-text outputs
# 768-dim vectors — pinning the column to that dimension, not making it
# configurable, mirrors invariant #8: changing the embedding model is a
# model-pin change (`ModelPin`, role=EMBEDDING), not a runtime option.
_EMBEDDING_DIM = 768


class Base(DeclarativeBase):
    pass


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)


# --------------------------------------------------------------------------- #
# Enums — every one of these is a closed vocabulary. Adding a
# value later is a migration, same as adding a column.
# --------------------------------------------------------------------------- #


class ScanRunStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanTrigger(enum.StrEnum):
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    WEBHOOK = "webhook"
    EVENT = "event"
    INGEST = "ingest"


class AssetType(enum.StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"
    HTTP_SERVICE = "http_service"
    TCP_SERVICE = "tcp_service"
    CLOUD_RESOURCE = "cloud_resource"
    REPO = "repo"
    CERT = "cert"
    ASN = "asn"
    NETBLOCK = "netblock"
    SAAS_TENANT = "saas_tenant"
    MOBILE_APP = "mobile_app"
    LLM_ENDPOINT = "llm_endpoint"
    VECTOR_DB = "vector_db"
    MCP_SERVER = "mcp_server"
    MODEL_REGISTRY = "model_registry"
    AI_AGENT_WEBHOOK = "ai_agent_webhook"
    # Stage 11b's remaining three named asset types —
    # llm_endpoint/mcp_server/model_registry/vector_db (vector_store)
    # already existed from Stage 0's forward-looking schema.
    NOTEBOOK = "notebook"
    AI_APP = "ai_app"
    AI_SAAS_TENANT = "ai_saas_tenant"
    # Stage 14 — containers/Kubernetes.
    CONTAINER_IMAGE = "container_image"
    K8S_CLUSTER = "k8s_cluster"
    K8S_WORKLOAD = "k8s_workload"


class AssetEdgeRelation(enum.StrEnum):
    RESOLVES_TO = "resolves_to"
    HOSTED_ON = "hosted_on"
    SERVES = "serves"
    REDIRECTS_TO = "redirects_to"
    CNAME_TO = "cname_to"
    ISSUED_FOR = "issued_for"
    OWNED_BY = "owned_by"
    DEPLOYED_FROM = "deployed_from"
    SAME_ORG_AS = "same_org_as"


class ChangeEventKind(enum.StrEnum):
    ASSET_NEW = "ASSET_NEW"
    ASSET_GONE = "ASSET_GONE"
    PORT_OPENED = "PORT_OPENED"
    PORT_CLOSED = "PORT_CLOSED"
    TECH_CHANGED = "TECH_CHANGED"
    DECOMMISSION_CANDIDATE = "DECOMMISSION_CANDIDATE"
    CERT_CHANGED = "CERT_CHANGED"
    DNS_CHANGED = "DNS_CHANGED"
    TAKEOVER_RISK = "TAKEOVER_RISK"
    AUTH_REMOVED = "AUTH_REMOVED"
    WENT_PUBLIC = "WENT_PUBLIC"
    CONTENT_CHANGED = "CONTENT_CHANGED"


class Severity(enum.StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvidenceKind(enum.StrEnum):
    HTTP_RESPONSE = "http_response"
    TLS_CERT = "tls_cert"
    DNS_RECORD = "dns_record"
    PORT_BANNER = "port_banner"
    SCREENSHOT = "screenshot"
    NUCLEI_RESULT = "nuclei_result"
    GIT_SECRET = "git_secret"
    CLOUD_CONFIG = "cloud_config"
    WHOIS = "whois"
    ASN_RECORD = "asn_record"
    FAVICON_HASH = "favicon_hash"
    JS_ENDPOINT = "js_endpoint"
    VERIFICATION_RESULT = "verification_result"
    EXTERNAL_FINDING = "external_finding"


class FindingDetector(enum.StrEnum):
    RULE = "rule"
    NUCLEI = "nuclei"
    LLM = "llm"
    MANUAL = "manual"
    EXTERNAL = "external"


class FindingStatus(enum.StrEnum):
    NEW = "new"
    TRIAGING = "triaging"
    TRIAGED = "triaged"
    ROUTED = "routed"
    ACCEPTED_RISK = "accepted_risk"
    VERIFICATION_PENDING = "verification_pending"
    FIXED = "fixed"
    REGRESSED = "regressed"
    SUPPRESSED = "suppressed"


class FindingEvidenceRole(enum.StrEnum):
    PRIMARY = "primary"
    SUPPORTING = "supporting"
    CONTEXT = "context"


class VerdictPassType(enum.StrEnum):
    BULK = "bulk"
    ESCALATION = "escalation"


class VerdictValue(enum.StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NOT_EXPLOITABLE = "not_exploitable"
    NEEDS_HUMAN = "needs_human"


class OwnerType(enum.StrEnum):
    USER = "user"
    TEAM = "team"


class OwnershipSource(enum.StrEnum):
    """Stage 3's 8-source confidence table. `IAC` is reserved for a
    future source reading `Owner`-style tags directly off Terraform resource
    blocks — Stage 3 only implements the state→repo→CODEOWNERS pipeline
    (`CODEOWNERS`), not a direct-tag variant. `DNS_AUDIT` (Route53/Cloudflare
    audit log, needs live API credentials this project has no way to test
    against) and `INFERENCE` (LLM-based, needs Stage 5's `llm/provider.py`,
    which doesn't exist yet) are reserved but unimplemented this stage —
    see kiyooo/enrich/ownership/sources.py.
    """

    CLOUD_TAG = "cloud_tag"
    IAC = "iac"
    CODEOWNERS = "codeowners"
    DNS_AUDIT = "dns_audit"
    TEAM_PATTERN = "team_pattern"
    GIT_BLAME = "git_blame"
    SIBLING_ASSET = "sibling_asset"
    INFERENCE = "inference"
    MANUAL = "manual"


class TicketSystem(enum.StrEnum):
    JIRA = "jira"
    LINEAR = "linear"
    GITHUB = "github"
    SERVICENOW = "servicenow"
    # Stage 7's generic-webhook sink — the "no vendor tenant to test
    # against" real+testable pick, same role CSV played for Stage 1b.
    WEBHOOK = "webhook"


class ExternalFindingSystem(enum.StrEnum):
    MANDIANT_ASM = "mandiant_asm"
    QUALYS = "qualys"
    TENABLE = "tenable"
    WIZ = "wiz"
    DEFENDER_EASM = "defender_easm"
    NUCLEI_JSON = "nuclei_json"
    NESSUS = "nessus"
    CUSTOM = "custom"
    # Stage 13 — Prowler (OSS, Apache-2.0) cloud posture audits.
    # A distinct value rather than CUSTOM: unlike the generic REST connector,
    # Prowler's config shape (`ingest/adapters/prowler.py`'s `ProwlerConfig`)
    # is fixed and dispatch (which parser runs) needs to key off `system`.
    PROWLER = "prowler"
    # Stage 14 — Trivy (OSS, Apache-2.0) container image + k8s
    # cluster scanning. Same reasoning as PROWLER above.
    TRIVY = "trivy"
    # Stage 15 — TruffleHog (OSS engine, AGPL-3.0) verified
    # secret scanning in source repos. Same reasoning as PROWLER above.
    TRUFFLEHOG = "trufflehog"
    # Stage 16 — mobile static analysis (apktool + reused
    # TruffleHog filesystem scan). Same reasoning as PROWLER above.
    MOBILE_STATIC = "mobile_static"


class ApprovalDraftKind(enum.StrEnum):
    TICKET = "ticket"
    EMAIL = "email"
    SLACK = "slack"
    COMMENT = "comment"


class ApprovalStatus(enum.StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    EDITED = "edited"
    REJECTED = "rejected"
    EXPIRED = "expired"


class LlmCallPurpose(enum.StrEnum):
    ADJUDICATE = "adjudicate"
    VERIFY_PLAN = "verify_plan"
    OWNERSHIP = "ownership"
    REMEDIATION = "remediation"


class IdentifierKind(enum.StrEnum):
    CVE = "cve"
    CVSS_VECTOR = "cvss_vector"
    VERSION = "version"
    HOSTNAME = "hostname"
    PACKAGE = "package"
    CWE = "cwe"


class IdentifierSource(enum.StrEnum):
    EVIDENCE = "evidence"
    MODEL = "model"


class IdentifierAuthority(enum.StrEnum):
    NVD = "nvd"
    KEV = "kev"
    OSV = "osv"
    DNS = "dns"
    EVIDENCE = "evidence"


class IdentifierStatus(enum.StrEnum):
    VERIFIED = "verified"
    NOT_FOUND = "not_found"
    MISMATCH = "mismatch"
    HALLUCINATED = "hallucinated"


class ModelPinRole(enum.StrEnum):
    BULK = "bulk"
    ESCALATION = "escalation"
    EMBEDDING = "embedding"


class ScopeDecision(enum.StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRES_CONFIRM = "requires_confirm"


class OrgRelationship(enum.StrEnum):
    SELF = "self"
    SUBSIDIARY = "subsidiary"
    ACQUISITION = "acquisition"
    BRAND = "brand"
    THIRD_PARTY = "third_party"
    PROSPECT = "prospect"


class SeedKind(enum.StrEnum):
    """A seed's `kind` decides what `build_org_scope_overlay` (`recon/scope.py`)
    can do with it. `GITHUB_ORG`/`SAAS_TENANT`/`BRAND_TERM` can be added via
    `kiyooo seed add` — they're real seed kinds per the spec — but none of
    them identify a network target (a host, an IP, an ASN, a cloud account),
    so `ScopeGuard` has nothing to check them against yet. They're stored,
    not enforced, until Part D §2's expansion step exists.
    """

    APEX_DOMAIN = "apex_domain"
    WILDCARD = "wildcard"
    SUBDOMAIN = "subdomain"
    URL = "url"
    IP = "ip"
    CIDR = "cidr"
    ASN = "asn"
    CLOUD_ACCOUNT = "cloud_account"
    GITHUB_ORG = "github_org"
    SAAS_TENANT = "saas_tenant"
    BRAND_TERM = "brand_term"
    EMAIL_DOMAIN = "email_domain"


class ScopeAction(enum.StrEnum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


class ExclusionSource(enum.StrEnum):
    SHIPPED_DEFAULT = "shipped_default"
    USER = "user"
    AUTO_CDN = "auto_cdn"
    AUTO_SHARED_HOST = "auto_shared_host"


# --------------------------------------------------------------------------- #
# Tables
# --------------------------------------------------------------------------- #


class ScanRun(Base):
    __tablename__ = "scan_run"

    id: Mapped[uuid.UUID] = _uuid_pk()
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[ScanRunStatus] = mapped_column(
        SAEnum(ScanRunStatus, name="scan_run_status"), nullable=False
    )
    scope_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    trigger: Mapped[ScanTrigger] = mapped_column(SAEnum(ScanTrigger, name="scan_trigger"))


class Asset(Base):
    __tablename__ = "asset"
    __table_args__ = (UniqueConstraint("type", "value", name="uq_asset_type_value"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    type: Mapped[AssetType] = mapped_column(SAEnum(AssetType, name="asset_type"), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    confidence_in_scope: Mapped[float] = mapped_column(Float, nullable=False)
    scope_reason: Mapped[str | None] = mapped_column(Text)
    attributes: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, default=dict)


class AssetEdge(Base):
    __tablename__ = "asset_edge"

    id: Mapped[uuid.UUID] = _uuid_pk()
    src_asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset.id", ondelete="CASCADE"), nullable=False
    )
    dst_asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset.id", ondelete="CASCADE"), nullable=False
    )
    relation: Mapped[AssetEdgeRelation] = mapped_column(
        SAEnum(AssetEdgeRelation, name="asset_edge_relation"), nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    discovered_by: Mapped[str] = mapped_column(String(128), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AssetSnapshot(Base):
    __tablename__ = "asset_snapshot"

    id: Mapped[uuid.UUID] = _uuid_pk()
    scan_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_run.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset.id", ondelete="CASCADE"), nullable=False
    )
    state_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ChangeEvent(Base):
    __tablename__ = "change_event"

    id: Mapped[uuid.UUID] = _uuid_pk()
    scan_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_run.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[ChangeEventKind] = mapped_column(
        SAEnum(ChangeEventKind, name="change_event_kind"), nullable=False
    )
    before: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    after: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    severity_hint: Mapped[Severity | None] = mapped_column(SAEnum(Severity, name="severity"))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Evidence(Base):
    __tablename__ = "evidence"

    # Human-readable per ev_<scan>_<n>, assigned by the bundler/writer,
    # not the database.
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_run.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[EvidenceKind] = mapped_column(
        SAEnum(EvidenceKind, name="evidence_kind"), nullable=False
    )
    source_tool: Mapped[str] = mapped_column(String(128), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    content_ref: Mapped[str | None] = mapped_column(String(1024))
    content_inline: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    redacted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # normalize/injection.py's canary scan sets this on
    # ingest. Downstream, §4.5.4 inverts the triage default on any finding
    # whose bundle includes evidence flagged here — never auto-closeable.
    injection_suspected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class Finding(Base):
    __tablename__ = "finding"

    id: Mapped[uuid.UUID] = _uuid_pk()
    scan_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_run.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset.id", ondelete="CASCADE"), nullable=False
    )
    category_id: Mapped[str] = mapped_column(String(128), nullable=False)
    raw_severity: Mapped[Severity] = mapped_column(
        SAEnum(Severity, name="severity"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    detector: Mapped[FindingDetector] = mapped_column(
        SAEnum(FindingDetector, name="finding_detector"), nullable=False
    )
    detector_ref: Mapped[str | None] = mapped_column(String(256))
    # Stable dedupe key; survives rescans. See fingerprint rule in the design —
    # never includes the raw IP for anything behind a load balancer.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    cluster_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), index=True)
    status: Mapped[FindingStatus] = mapped_column(
        SAEnum(FindingStatus, name="finding_status"), nullable=False, default=FindingStatus.NEW
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("finding.id", ondelete="CASCADE"), primary_key=True
    )
    evidence_id: Mapped[str] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[FindingEvidenceRole] = mapped_column(
        SAEnum(FindingEvidenceRole, name="finding_evidence_role"), nullable=False
    )


class Verdict(Base):
    __tablename__ = "verdict"

    id: Mapped[uuid.UUID] = _uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("finding.id", ondelete="CASCADE"), nullable=False
    )
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    model_version: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(64), nullable=False)
    pass_type: Mapped[VerdictPassType] = mapped_column(
        SAEnum(VerdictPassType, name="verdict_pass_type"), nullable=False
    )
    verdict: Mapped[VerdictValue] = mapped_column(
        SAEnum(VerdictValue, name="verdict_value"), nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    adjusted_severity: Mapped[Severity] = mapped_column(
        SAEnum(Severity, name="severity"), nullable=False
    )
    reasoning: Mapped[str] = mapped_column(Text, nullable=False)
    # Stage 7's ticket contract needs this for the "why it
    # matters here" block; the model always produces it (VerdictSchema
    # requires it) but nothing persisted it before Stage 7.
    business_impact_hypothesis: Mapped[str] = mapped_column(Text, nullable=False)
    citations: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    compensating_controls: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )
    exploitability: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    remediation: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tokens_in: Mapped[int] = mapped_column(Integer, nullable=False)
    tokens_out: Mapped[int] = mapped_column(Integer, nullable=False)
    cost_usd: Mapped[float] = mapped_column(Numeric(10, 6), nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class HumanReview(Base):
    __tablename__ = "human_review"

    id: Mapped[uuid.UUID] = _uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("finding.id", ondelete="CASCADE"), nullable=False
    )
    reviewer: Mapped[str] = mapped_column(String(256), nullable=False)
    agreed_with_model: Mapped[bool] = mapped_column(Boolean, nullable=False)
    final_verdict: Mapped[VerdictValue] = mapped_column(
        SAEnum(VerdictValue, name="verdict_value"), nullable=False
    )
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    promote_to_rule: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # `triage/memory.py`'s pgvector similarity source — an embedding of
    # `rationale` (+ finding summary), generated on write. Nullable: rows
    # written before an embedding provider was configured, or if embedding
    # generation itself failed, simply don't participate in retrieval.
    embedding: Mapped[list[float] | None] = mapped_column(Vector(_EMBEDDING_DIM))


class Ownership(Base):
    """One row per (asset, source): each ownership source that applies to an
    asset gets its own candidate row, not a single merged row — the design
    Stage 3's merge rule ("highest confidence wins; if top two disagree and
    both >=0.8, mark disputed... never silently pick one") is computed by
    querying all of an asset's rows, not by collapsing them at write time.
    See `kiyooo/enrich/ownership/merge.py`.
    """

    __tablename__ = "ownership"
    __table_args__ = (UniqueConstraint("asset_id", "source", name="uq_ownership_asset_source"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset.id", ondelete="CASCADE"), nullable=False
    )
    owner_type: Mapped[OwnerType] = mapped_column(
        SAEnum(OwnerType, name="owner_type"), nullable=False
    )
    owner_ref: Mapped[str] = mapped_column(String(256), nullable=False)
    manager_ref: Mapped[str | None] = mapped_column(String(256))
    source: Mapped[OwnershipSource] = mapped_column(
        SAEnum(OwnershipSource, name="ownership_source"), nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    evidence_note: Mapped[str | None] = mapped_column(Text)
    verified_by_human: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class Control(Base):
    """One row per (asset, control_id): re-running `detect/controls.py`
    updates the existing row's `detected_at`/`evidence_id` rather than
    accumulating duplicates every scan — the same idempotency requirement
    Stage 3's `Ownership` table has (see its docstring).
    """

    __tablename__ = "control"
    __table_args__ = (UniqueConstraint("asset_id", "control_id", name="uq_control_asset_control"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset.id", ondelete="CASCADE"), nullable=False
    )
    control_id: Mapped[str] = mapped_column(String(128), nullable=False)
    detected_by: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_id: Mapped[str | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True
    )
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Ticket(Base):
    __tablename__ = "ticket"

    id: Mapped[uuid.UUID] = _uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("finding.id", ondelete="CASCADE"), nullable=False
    )
    system: Mapped[TicketSystem] = mapped_column(
        SAEnum(TicketSystem, name="ticket_system"), nullable=False
    )
    external_key: Mapped[str | None] = mapped_column(String(256))
    assignee: Mapped[str | None] = mapped_column(String(256))
    cc: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ExternalFindingSource(Base):
    """One configured connection to an external ASM/VM tool. `system`
    stays a coarse enum (a handful of tools get a hand-written adapter
    with a pure `parse_*()`, e.g. `mandiant.py`/`tenable.py`); anything
    else is `CUSTOM` and driven entirely by `config`, whose shape
    `ingest/adapters/generic_rest.py`'s `GenericRestConfig` validates —
    base URL, auth (via `credential_ref`, never a raw secret), and a
    field mapping from the vendor's JSON shape onto `ImportedFinding`.
    `name` disambiguates multiple `CUSTOM` sources (two tenants of the
    same tool, or two different tools) since `system` alone no longer
    identifies a source uniquely once more than one is `CUSTOM`.
    """

    __tablename__ = "external_finding_source"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    system: Mapped[ExternalFindingSystem] = mapped_column(
        SAEnum(ExternalFindingSystem, name="external_finding_system"), nullable=False
    )
    config: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, default=dict)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_cursor: Mapped[str | None] = mapped_column(String(512))
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class ExternalFindingRaw(Base):
    __tablename__ = "external_finding_raw"
    __table_args__ = (
        UniqueConstraint("source_id", "external_id", name="uq_external_finding_source_external_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    source_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("external_finding_source.id", ondelete="CASCADE"), nullable=False
    )
    external_id: Mapped[str] = mapped_column(String(512), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    mapped_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("finding.id", ondelete="SET NULL")
    )
    mapping_status: Mapped[str] = mapped_column(String(64), nullable=False)
    mapping_notes: Mapped[str | None] = mapped_column(Text)


class Approval(Base):
    __tablename__ = "approval"

    id: Mapped[uuid.UUID] = _uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("finding.id", ondelete="CASCADE"), nullable=False
    )
    draft_kind: Mapped[ApprovalDraftKind] = mapped_column(
        SAEnum(ApprovalDraftKind, name="approval_draft_kind"), nullable=False
    )
    rendered_body: Mapped[str] = mapped_column(Text, nullable=False)
    rendered_subject: Mapped[str | None] = mapped_column(String(512))
    target_assignee: Mapped[str | None] = mapped_column(String(256))
    target_cc: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    status: Mapped[ApprovalStatus] = mapped_column(
        SAEnum(ApprovalStatus, name="approval_status"),
        nullable=False,
        default=ApprovalStatus.PENDING,
    )
    reviewer: Mapped[str | None] = mapped_column(String(256))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    edit_diff: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    external_key: Mapped[str | None] = mapped_column(String(256))


class LlmCallLog(Base):
    __tablename__ = "llm_call_log"

    id: Mapped[uuid.UUID] = _uuid_pk()
    scan_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_run.id", ondelete="SET NULL")
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("finding.id", ondelete="SET NULL")
    )
    purpose: Mapped[LlmCallPurpose] = mapped_column(
        SAEnum(LlmCallPurpose, name="llm_call_purpose"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    model_digest: Mapped[str | None] = mapped_column(String(128))
    prompt_version: Mapped[str] = mapped_column(String(64), nullable=False)
    system_prompt_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    messages: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    raw_response: Mapped[str | None] = mapped_column(Text)
    refused: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    refusal_reason: Mapped[str | None] = mapped_column(Text)
    retry_of_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("llm_call_log.id", ondelete="SET NULL")
    )
    tokens_in: Mapped[int] = mapped_column(Integer, nullable=False)
    tokens_out: Mapped[int] = mapped_column(Integer, nullable=False)
    cost_usd: Mapped[float] = mapped_column(Numeric(10, 6), nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class IdentifierVerification(Base):
    __tablename__ = "identifier_verification"

    id: Mapped[uuid.UUID] = _uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("finding.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[IdentifierKind] = mapped_column(
        SAEnum(IdentifierKind, name="identifier_kind"), nullable=False
    )
    claimed_value: Mapped[str] = mapped_column(String(512), nullable=False)
    source: Mapped[IdentifierSource] = mapped_column(
        SAEnum(IdentifierSource, name="identifier_source"), nullable=False
    )
    resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    authority: Mapped[IdentifierAuthority | None] = mapped_column(
        SAEnum(IdentifierAuthority, name="identifier_authority")
    )
    resolved_value: Mapped[str | None] = mapped_column(String(512))
    status: Mapped[IdentifierStatus] = mapped_column(
        SAEnum(IdentifierStatus, name="identifier_status"), nullable=False
    )
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ModelPin(Base):
    """Which provider/model runs each role (bulk/escalation/embedding) —
    `provider` is a free-text name, not a closed enum: "ollama" and
    "anthropic" are the two this project ships a dedicated client for,
    but anything else (openai, openrouter, vllm, azure_openai, bedrock, a
    self-hosted server, literally any name) is a bring-your-own-model
    provider, served by `OpenAiCompatibleProvider` against `endpoint_url`
    — the request/response shape most non-Anthropic providers share.
    `credential_ref` never holds a raw key (invariant #6/#7) — only a
    pointer like `"env:OPENAI_API_KEY"`, resolved at call time.
    """

    __tablename__ = "model_pin"

    id: Mapped[uuid.UUID] = _uuid_pk()
    role: Mapped[ModelPinRole] = mapped_column(
        SAEnum(ModelPinRole, name="model_pin_role"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    digest: Mapped[str] = mapped_column(String(128), nullable=False)
    # NULL for "ollama"/"anthropic" (they have a built-in default —
    # settings.llm_base_url / the hardcoded Anthropic API root) — required
    # for any bring-your-own-model provider, which has no default to fall
    # back to.
    endpoint_url: Mapped[str | None] = mapped_column(String(512))
    credential_ref: Mapped[str | None] = mapped_column(String(128))
    pinned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    pinned_by: Mapped[str] = mapped_column(String(256), nullable=False)
    eval_run_id: Mapped[str | None] = mapped_column(String(128))
    changelog_note: Mapped[str] = mapped_column(Text, nullable=False)
    superseded_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("model_pin.id", ondelete="SET NULL")
    )


class ModuleToggle(Base):
    """Whether an optional attack-surface module (cloud, containers, repos,
    mobile, attack-paths) is switched on in the UI — Stage 13-17's domain
    pages are additive scan sources, not core recon, so a user who hasn't
    onboarded a domain yet can turn its nav entry and page off rather than
    stare at an empty "add a cloud account" card.

    `module_key` is the primary key (not a UUID row) since this is a small,
    fixed set of singleton settings, one row per module — same shape as a
    feature-flag table, not an aggregate with history. Toggling is a UI
    convenience only: it never gates the API, CLI, or ingest pipeline, so
    flipping it off never hides or drops data already ingested.
    """

    __tablename__ = "module_toggle"

    module_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditLog(Base):
    """Append-only record of every ScopeGuard decision.

    Every outbound-capable action — allowed, denied, or requiring confirmation —
    gets a row here before any packet can be sent. This table is the evidence
    that invariant #2 (all outbound activity routes through ScopeGuard) held for
    a given run; it is never updated or deleted, only appended to.
    """

    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = _uuid_pk()
    scan_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_run.id", ondelete="SET NULL")
    )
    # Stage 6: verification calls (`verify/executor.py`) are ScopeGuard
    # checks made on behalf of one specific finding, not a scan run at
    # large — nullable because Stage 1's recon-time checks have no finding
    # yet to point to.
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("finding.id", ondelete="SET NULL")
    )
    tool: Mapped[str] = mapped_column(String(128), nullable=False)
    target: Mapped[str] = mapped_column(String(2048), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False)
    decision: Mapped[ScopeDecision] = mapped_column(
        SAEnum(ScopeDecision, name="scope_decision"), nullable=False
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Organization(Base):
    """kiyooo-easm-standalone.md Part D §1, build item 1 (§10) — the
    top-level tenant, and its subsidiaries via `parent_org_id`. No ORM
    `relationship()` graph, same rule the rest of this file follows —
    `OrganizationRepository.list_children` does an explicit query.

    `third_party` forces `active_scanning_allowed = False` — mirrors
    `ScopeConfig._third_party_is_always_passive` (config.py), enforced here
    at the repository create-path instead of a static file validator, since
    an org is created at CLI runtime, not loaded from `scope.yaml`.
    """

    __tablename__ = "organization"
    __table_args__ = (UniqueConstraint("slug", name="uq_organization_slug"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    slug: Mapped[str] = mapped_column(String(128), nullable=False)
    parent_org_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organization.id", ondelete="RESTRICT")
    )
    relationship: Mapped[OrgRelationship] = mapped_column(
        SAEnum(OrgRelationship, name="org_relationship"), nullable=False
    )
    legal_entity_name: Mapped[str | None] = mapped_column(String(256))
    country: Mapped[str | None] = mapped_column(String(2))
    active_scanning_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    authorization_id: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by: Mapped[str] = mapped_column(String(256), nullable=False)


class Seed(Base):
    """Part D §1 — what a human explicitly asserted. Distinct from `Asset`:
    a seed is provenance (who asserted this, when, include or exclude), an
    asset is a discovered thing. `verified`/item 2's ownership-verification
    gate is stored here but **not enforced** by `ScopeGuard` in build item
    1 — that enforcement is item 2's DoD, not this one's.

    `active_scan_allowed` (NULL = defer to the org's `active_scanning_
    allowed`) is likewise stored but **not yet enforced per-seed** —
    `ScopeGuard` currently only checks the org-level flag (`recon/scope.py`,
    `ScopeGuard._active_scanning_authorized`'s `org_active_scanning_
    allowed` parameter), not which specific seed a target matched through.
    A seed can't yet widen or narrow active-scan authorization on its own;
    only the org's own setting does. Fixing this needs the overlay to track
    per-entry provenance (which seed matched, not just the value it
    contributed), which build item 1 doesn't do.

    Soft-disable via `disabled_at` only; a seed is never hard-deleted, same
    as everything else in this project a human decision touches.
    """

    __tablename__ = "seed"

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organization.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[SeedKind] = mapped_column(SAEnum(SeedKind, name="seed_kind"), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    scope_action: Mapped[ScopeAction] = mapped_column(
        SAEnum(ScopeAction, name="scope_action"), nullable=False, default=ScopeAction.INCLUDE
    )
    # NULL = defer to the org's active_scanning_allowed setting.
    active_scan_allowed: Mapped[bool | None] = mapped_column(Boolean)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    note: Mapped[str | None] = mapped_column(Text)
    added_by: Mapped[str] = mapped_column(String(256), nullable=False)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Exclusion(Base):
    """Part D §1 — global (`org_id IS NULL`) or org-level, always beats
    include. Reuses `SeedKind` for `kind`: same matching vocabulary as a
    seed, same enforcement limits (`recon/scope.py`'s
    `build_org_scope_overlay` can only fold hostname/wildcard/CIDR-kind
    exclusions into `ScopeGuard`'s existing exclude check — an ASN- or
    cloud-account-kind exclusion is stored, not yet enforced, since
    `ScopeGuard` never checked exclude against those forms either).
    """

    __tablename__ = "exclusion"

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organization.id", ondelete="CASCADE")
    )
    kind: Mapped[SeedKind] = mapped_column(SAEnum(SeedKind, name="seed_kind"), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[ExclusionSource] = mapped_column(
        SAEnum(ExclusionSource, name="exclusion_source"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
