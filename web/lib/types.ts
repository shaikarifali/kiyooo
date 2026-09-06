// Mirrors kiyooo/api/schemas.py — kept in sync by hand since there's no
// FastAPI/Next.js shared codegen step in this project yet. If these two
// files drift, the OpenAPI spec at /openapi.json is the source of truth.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingStatus =
  | "new"
  | "triaging"
  | "triaged"
  | "routed"
  | "accepted_risk"
  | "verification_pending"
  | "fixed"
  | "regressed"
  | "suppressed";

export type VerdictValue = "true_positive" | "false_positive" | "not_exploitable" | "needs_human";

export type FindingDetector = "rule" | "nuclei" | "llm" | "manual" | "external";

export type OwnerType = "user" | "team";

export type AssetOut = {
  id: string;
  type: string;
  value: string;
  first_seen: string;
  last_seen: string;
  is_active: boolean;
  confidence_in_scope: number;
  scope_reason: string | null;
  attributes: Record<string, unknown>;
};

export type EvidenceOut = {
  id: string;
  kind: string;
  source_tool: string;
  collected_at: string;
  content_inline: Record<string, unknown> | null;
  redacted: boolean;
  injection_suspected: boolean;
};

export type VerdictOut = {
  id: string;
  model: string;
  prompt_version: string;
  verdict: VerdictValue;
  confidence: number;
  adjusted_severity: Severity;
  reasoning: string;
  business_impact_hypothesis: string;
  citations: string[];
  compensating_controls: string[];
  exploitability: Record<string, unknown> | null;
  remediation: Record<string, unknown> | null;
  cost_usd: number;
  created_at: string;
};

export type FindingOut = {
  id: string;
  scan_run_id: string;
  asset_id: string;
  category_id: string;
  raw_severity: Severity;
  title: string;
  description: string | null;
  detector: FindingDetector;
  status: FindingStatus;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
};

export type IdentifierKind = "cve" | "cvss_vector" | "version" | "hostname" | "package" | "cwe";

export type IdentifierSource = "evidence" | "model";

export type IdentifierAuthority = "nvd" | "kev" | "osv" | "dns" | "evidence";

export type IdentifierStatus = "verified" | "not_found" | "mismatch" | "hallucinated";

export type IdentifierVerificationOut = {
  kind: IdentifierKind;
  claimed_value: string;
  source: IdentifierSource;
  resolved: boolean;
  authority: IdentifierAuthority | null;
  resolved_value: string | null;
  status: IdentifierStatus;
  checked_at: string;
};

export type HumanReviewOut = {
  id: string;
  reviewer: string;
  agreed_with_model: boolean;
  final_verdict: VerdictValue;
  rationale: string;
  created_at: string;
};

export type FindingDetailOut = {
  finding: FindingOut;
  asset: AssetOut;
  latest_verdict: VerdictOut | null;
  evidence: EvidenceOut[];
  identifier_verifications: IdentifierVerificationOut[];
  human_reviews: HumanReviewOut[];
};

export type ChangeEventOut = {
  id: string;
  scan_run_id: string;
  asset_id: string;
  kind: string;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  severity_hint: Severity | null;
  occurred_at: string;
};

export type ScanRunOut = {
  id: string;
  started_at: string;
  finished_at: string | null;
  status: string;
  trigger: string;
};

export type AssetEdgeOut = {
  src_asset_id: string;
  dst_asset_id: string;
  relation: string;
  confidence: number;
  discovered_by: string;
};

export type OwnershipOut = {
  owner_type: OwnerType;
  owner_ref: string;
  source: string;
  confidence: number;
  note: string | null;
};

export type CoverageStatsOut = {
  total_assets: number;
  active_assets: number;
  resolved_ownership: number;
  disputed_ownership: number;
  orphan_ownership: number;
  pct_owner_confidence_gte_0_8: number;
};

export type ReviewRequest = {
  verdict: VerdictValue;
  rationale: string;
  reviewer: string;
};

export type ReviewOut = {
  finding_id: string;
  agreed_with_model: boolean;
  final_verdict: VerdictValue;
};

export type OwnershipOverrideRequest = {
  owner_type: OwnerType;
  owner_ref: string;
  note?: string | null;
  reviewer: string;
};

export type TeamSummaryOut = {
  id: string;
  slack: string | null;
  manager: string;
  members: string[];
};

// kiyooo-easm-standalone.md Part D §1 — org + seed + exclusion.

export type OrgRelationship =
  | "self"
  | "subsidiary"
  | "acquisition"
  | "brand"
  | "third_party"
  | "prospect";

export type SeedKind =
  | "apex_domain"
  | "wildcard"
  | "subdomain"
  | "url"
  | "ip"
  | "cidr"
  | "asn"
  | "cloud_account"
  | "github_org"
  | "saas_tenant"
  | "brand_term"
  | "email_domain";

export type ScopeAction = "include" | "exclude";

export type ExclusionSource = "shipped_default" | "user" | "auto_cdn" | "auto_shared_host";

export type OrganizationOut = {
  id: string;
  name: string;
  slug: string;
  parent_org_id: string | null;
  relationship: OrgRelationship;
  legal_entity_name: string | null;
  country: string | null;
  active_scanning_allowed: boolean;
  authorization_id: string | null;
  created_at: string;
  created_by: string;
};

export type OrganizationCreateRequest = {
  slug: string;
  name: string;
  parent_org_id?: string | null;
  relationship?: OrgRelationship;
  legal_entity_name?: string | null;
  country?: string | null;
  active_scanning_allowed?: boolean;
  authorization_id?: string | null;
  created_by: string;
};

export type SeedOut = {
  id: string;
  org_id: string;
  kind: SeedKind;
  value: string;
  scope_action: ScopeAction;
  active_scan_allowed: boolean | null;
  verified: boolean;
  note: string | null;
  added_by: string;
  added_at: string;
  disabled_at: string | null;
};

export type SeedCreateRequest = {
  org_id: string;
  kind: SeedKind;
  value: string;
  scope_action?: ScopeAction;
  active_scan_allowed?: boolean | null;
  note?: string | null;
  added_by: string;
};

export type ExclusionOut = {
  id: string;
  org_id: string | null;
  kind: SeedKind;
  value: string;
  reason: string;
  source: ExclusionSource;
  created_at: string;
};

export type ExclusionCreateRequest = {
  org_id?: string | null;
  kind: SeedKind;
  value: string;
  reason: string;
  source?: ExclusionSource;
};

export type CategorySummary = {
  id: string;
  name: string;
  severity_base: string;
  enabled: boolean;
};

export type CaseAsset = {
  type: string;
  value: string;
};

export type CaseEvidence = {
  kind: string;
  content: Record<string, unknown>;
};

export type CategoryPreviewRequest = {
  asset: CaseAsset;
  evidence: CaseEvidence[];
  kev_known_exploited_cves?: string[];
  epss_scores?: Record<string, number>;
};

export type PreviewResult = {
  matched: boolean;
  discriminator: string | null;
  evidence_ids: string[];
  error: string | null;
};

export type AgreementRow = {
  category_id: string;
  model: string;
  prompt_version: string;
  total: number;
  agreed: number;
  rate: number;
};

export type DashboardOut = {
  agreement: AgreementRow[];
  total_cost_usd: number;
  scan_run_count: number;
  cost_per_scan_run_usd: number;
  status_counts: Record<string, number>;
  verdict_counts: Record<string, number>;
  routed_severity_counts: Record<string, number>;
};

// Model configuration — mirrors `kiyooo providers list/pin/test`.

export type ModelPinRole = "bulk" | "escalation" | "embedding";

export type ModelPinOut = {
  id: string;
  role: ModelPinRole;
  provider: string;
  model: string;
  digest: string;
  endpoint_url: string | null;
  credential_ref: string | null;
  pinned_at: string;
  pinned_by: string;
  eval_run_id: string | null;
  changelog_note: string;
};

export type ModelPinCreateRequest = {
  role: ModelPinRole;
  provider: string;
  model: string;
  digest: string;
  pinned_by: string;
  changelog_note: string;
  endpoint_url?: string | null;
  credential_ref?: string | null;
  eval_run_id?: string | null;
};

export type RoleDefaultOut = {
  role: ModelPinRole;
  provider: string;
  model: string;
};

export type ProviderTestRequest = {
  provider: string;
  model: string;
  endpoint_url?: string | null;
  credential_ref?: string | null;
};

export type ProviderTestResultOut = {
  ok: boolean;
  latency_ms: number;
  detail: string;
  model_found: boolean | null;
};

// External finding ingest — mirrors `kiyooo ingest sources add/list` /
// `ingest/adapters/generic_rest.py`'s `GenericRestConfig`. "Point kiyooo
// at any REST/JSON-emitting ASM/VM tool" — no code change per vendor.

export type AssetType =
  | "domain"
  | "subdomain"
  | "ip"
  | "url"
  | "http_service"
  | "tcp_service"
  | "cloud_resource"
  | "repo"
  | "cert"
  | "asn"
  | "netblock"
  | "saas_tenant"
  | "mobile_app"
  | "llm_endpoint"
  | "vector_db"
  | "mcp_server"
  | "model_registry"
  | "ai_agent_webhook";

export type IngestAuthType = "none" | "bearer" | "header" | "basic";

export type IngestFieldMapping = {
  external_id: string;
  vendor_issue_type: string;
  title: string;
  vendor_severity: string;
  asset_value: string;
};

export type GenericRestConfig = {
  base_url: string;
  path: string;
  method: "GET" | "POST";
  auth_type: IngestAuthType;
  auth_header?: string | null;
  auth_value_template?: string | null;
  basic_username?: string | null;
  credential_ref?: string | null;
  request_body?: Record<string, unknown> | null;
  items_path?: string;
  field_mapping: IngestFieldMapping;
  default_asset_type: AssetType;
  since_param?: string | null;
  next_cursor_path?: string | null;
  cursor_param?: string | null;
  max_pages?: number;
};

export type IngestSourceOut = {
  id: string;
  name: string;
  system: string;
  config: GenericRestConfig;
  enabled: boolean;
  last_sync_at: string | null;
  last_cursor: string | null;
};

export type IngestSourceCreateRequest = {
  name: string;
  config: GenericRestConfig;
  enabled?: boolean;
};

export type IngestSyncResultOut = {
  mapped: number;
  unmapped: number;
};

export type UnmappedFindingOut = {
  id: string;
  source_id: string;
  source_name: string;
  external_id: string;
  mapping_notes: string | null;
  ingested_at: string;
};

export type IngestTestResultOut = {
  ok: boolean;
  item_count: number;
  mapped_preview: number;
  unmapped_preview: number;
  sample_titles: string[];
  error: string | null;
};

// Cloud posture — mirrors `ingest/adapters/prowler.py`'s
// `ProwlerConfig`. Point kiyooo at an AWS/Azure/GCP/Kubernetes account and
// audit it with Prowler (OSS, Apache-2.0); every finding still flows through
// the same category -> LLM triage -> human review pipeline as everything else.

export type CloudProvider = "aws" | "azure" | "gcp" | "kubernetes";

export type ProwlerConfig = {
  provider: CloudProvider;
  credential_env: Record<string, string>;
  extra_args: string[];
};

export type CloudAccountOut = {
  id: string;
  name: string;
  config: ProwlerConfig;
  enabled: boolean;
  last_sync_at: string | null;
};

export type CloudAccountCreateRequest = {
  name: string;
  config: ProwlerConfig;
  enabled?: boolean;
};

// Containers & Kubernetes — mirrors
// `ingest/adapters/trivy.py`'s `TrivyConfig`. Point kiyooo at a container
// image or a Kubernetes cluster and scan it with Trivy (OSS, Apache-2.0);
// same "candidate, not a finding" triage pipeline as everything else.

export type TrivyScanKind = "image" | "k8s";

export type TrivyConfig = {
  scan_kind: TrivyScanKind;
  target: string;
  credential_env: Record<string, string>;
  extra_args: string[];
};

export type ContainerScanOut = {
  id: string;
  name: string;
  config: TrivyConfig;
  enabled: boolean;
  last_sync_at: string | null;
};

export type ContainerScanCreateRequest = {
  name: string;
  config: TrivyConfig;
  enabled?: boolean;
};

// Source code & supply chain — mirrors
// `ingest/adapters/trufflehog.py`'s `TrufflehogConfig`. Point kiyooo at a
// git repo and scan it for verified live secrets with TruffleHog (OSS
// engine, AGPL-3.0); same "candidate, not a finding" triage pipeline.

export type TrufflehogConfig = {
  repo_url: string;
  credential_ref: string | null;
  extra_args: string[];
};

export type RepoScanOut = {
  id: string;
  name: string;
  config: TrufflehogConfig;
  enabled: boolean;
  last_sync_at: string | null;
};

export type RepoScanCreateRequest = {
  name: string;
  config: TrufflehogConfig;
  enabled?: boolean;
};

// Mobile static analysis — mirrors
// `ingest/adapters/mobile_static.py`'s `MobileScanConfig`. Android only —
// static analysis via apktool + a reused TruffleHog filesystem scan, no
// device/emulator/Frida involved anywhere.

export type MobilePlatform = "android";

export type MobileScanConfig = {
  platform: MobilePlatform;
  apk_path: string;
};

export type MobileScanOut = {
  id: string;
  name: string;
  config: MobileScanConfig;
  enabled: boolean;
  last_sync_at: string | null;
};

export type MobileScanCreateRequest = {
  name: string;
  config: MobileScanConfig;
  enabled?: boolean;
};

// Attack path engine — computed on demand, mirrors
// `graph/attack_path.py`'s dataclasses.

export type AttackPathHopOut = {
  asset_id: string;
  asset_type: string;
  asset_value: string;
  finding_id: string | null;
  finding_category_id: string | null;
  finding_severity: string | null;
};

export type AttackPathOut = {
  hops: AttackPathHopOut[];
  score: number;
  sensitive_category_id: string;
};

export type ModuleKey = "cloud" | "containers" | "repos" | "mobile" | "attack_paths";

export type ModuleToggleOut = {
  module_key: ModuleKey;
  enabled: boolean;
  updated_at: string;
};
