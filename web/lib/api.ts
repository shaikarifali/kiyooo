// Thin fetch wrapper over kiyooo's FastAPI backend (kiyooo/api/app.py).
// No auth — see that module's docstring; RBAC/SSO is Stage 11's
// explicitly-deferred item.

import type {
  AssetEdgeOut,
  AssetOut,
  AttackPathOut,
  CategoryPreviewRequest,
  CategorySummary,
  ChangeEventOut,
  CloudAccountCreateRequest,
  CloudAccountOut,
  ContainerScanCreateRequest,
  ContainerScanOut,
  CoverageStatsOut,
  DashboardOut,
  ExclusionCreateRequest,
  ExclusionOut,
  FindingDetailOut,
  FindingOut,
  FindingStatus,
  GenericRestConfig,
  IngestSourceCreateRequest,
  IngestSourceOut,
  IngestSyncResultOut,
  IngestTestResultOut,
  MobileScanCreateRequest,
  MobileScanOut,
  ModelPinCreateRequest,
  ModelPinOut,
  ModuleKey,
  ModuleToggleOut,
  OrganizationCreateRequest,
  OrganizationOut,
  OwnershipOut,
  OwnershipOverrideRequest,
  PreviewResult,
  ProviderTestRequest,
  ProviderTestResultOut,
  RepoScanCreateRequest,
  RepoScanOut,
  ReviewOut,
  ReviewRequest,
  RoleDefaultOut,
  ScanRunOut,
  SeedCreateRequest,
  SeedOut,
  TeamSummaryOut,
  UnmappedFindingOut,
} from "./types";

// Same-origin, relative — next.config.mjs's rewrite proxies /api/* to the
// real backend server-side, so the browser never needs a second port/host.
// One URL for the whole product, no CORS preflight either (real same-
// origin now, not cross-origin-with-a-permissive-header).
const API_BASE = "";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
    cache: "no-store",
  });
  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      const body = await resp.json();
      detail = body.detail ?? JSON.stringify(body);
    } catch {
      // response wasn't JSON — fall back to statusText
    }
    throw new ApiError(resp.status, detail);
  }
  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

function qs(params: Record<string, string | number | string[] | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      for (const v of value) search.append(key, v);
    } else {
      search.set(key, String(value));
    }
  }
  const s = search.toString();
  return s ? `?${s}` : "";
}

export const api = {
  listChanges: (hours = 24) => request<ChangeEventOut[]>(`/api/changes${qs({ hours })}`),

  listFindings: (
    opts: { status?: FindingStatus; scan_run_id?: string; category_id?: string; limit?: number } = {},
  ) => request<FindingOut[]>(`/api/findings${qs(opts)}`),
  getFinding: (id: string) => request<FindingDetailOut>(`/api/findings/${id}`),
  submitReview: (findingId: string, body: ReviewRequest) =>
    request<ReviewOut>(`/api/findings/${findingId}/review`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  listAssets: (clauses: string[] = []) => request<AssetOut[]>(`/api/assets${qs({ q: clauses })}`),
  getAsset: (id: string) => request<AssetOut>(`/api/assets/${id}`),
  getAssetEdges: (id: string) => request<AssetEdgeOut[]>(`/api/assets/${id}/edges`),
  getOwnership: (assetId: string) =>
    request<OwnershipOut | null>(`/api/assets/${assetId}/ownership`),
  overrideOwnership: (assetId: string, body: OwnershipOverrideRequest) =>
    request<OwnershipOut>(`/api/assets/${assetId}/ownership`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  listScanRuns: (limit = 20) => request<ScanRunOut[]>(`/api/scan-runs${qs({ limit })}`),

  getCoverage: () => request<CoverageStatsOut>("/api/coverage"),

  listCategories: () => request<CategorySummary[]>("/api/categories"),
  previewCategory: (categoryId: string, body: CategoryPreviewRequest) =>
    request<PreviewResult>(`/api/categories/${categoryId}/preview`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  getDashboard: () => request<DashboardOut>("/api/dashboard"),

  listTeams: () => request<TeamSummaryOut[]>("/api/teams"),

  listOrganizations: () => request<OrganizationOut[]>("/api/organizations"),
  createOrganization: (body: OrganizationCreateRequest) =>
    request<OrganizationOut>("/api/organizations", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  listSeeds: (orgId: string, includeDisabled = false) =>
    request<SeedOut[]>(
      `/api/seeds${qs({ org_id: orgId, include_disabled: includeDisabled ? "true" : undefined })}`,
    ),
  createSeed: (body: SeedCreateRequest) =>
    request<SeedOut>("/api/seeds", { method: "POST", body: JSON.stringify(body) }),
  disableSeed: (seedId: string) =>
    request<SeedOut>(`/api/seeds/${seedId}/disable`, { method: "POST" }),

  listExclusions: (orgId?: string) =>
    request<ExclusionOut[]>(`/api/exclusions${qs({ org_id: orgId })}`),
  createExclusion: (body: ExclusionCreateRequest) =>
    request<ExclusionOut>("/api/exclusions", { method: "POST", body: JSON.stringify(body) }),

  listModelPins: () => request<ModelPinOut[]>("/api/model-pins"),
  listRoleDefaults: () => request<RoleDefaultOut[]>("/api/model-pins/defaults"),
  createModelPin: (body: ModelPinCreateRequest) =>
    request<ModelPinOut>("/api/model-pins", { method: "POST", body: JSON.stringify(body) }),
  testProvider: (body: ProviderTestRequest) =>
    request<ProviderTestResultOut>("/api/model-pins/test", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  listIngestSources: () => request<IngestSourceOut[]>("/api/ingest/sources"),
  createIngestSource: (body: IngestSourceCreateRequest) =>
    request<IngestSourceOut>("/api/ingest/sources", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateIngestSource: (sourceId: string, body: IngestSourceCreateRequest) =>
    request<IngestSourceOut>(`/api/ingest/sources/${sourceId}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  syncIngestSource: (sourceId: string) =>
    request<IngestSyncResultOut>(`/api/ingest/sources/${sourceId}/sync`, { method: "POST" }),
  listUnmappedFindings: (sourceId?: string) =>
    request<UnmappedFindingOut[]>(`/api/ingest/unmapped${qs({ source_id: sourceId })}`),
  testIngestSource: (config: GenericRestConfig) =>
    request<IngestTestResultOut>("/api/ingest/test", {
      method: "POST",
      body: JSON.stringify(config),
    }),

  listCloudAccounts: () => request<CloudAccountOut[]>("/api/cloud/accounts"),
  createCloudAccount: (body: CloudAccountCreateRequest) =>
    request<CloudAccountOut>("/api/cloud/accounts", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateCloudAccount: (accountId: string, body: CloudAccountCreateRequest) =>
    request<CloudAccountOut>(`/api/cloud/accounts/${accountId}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  syncCloudAccount: (accountId: string) =>
    request<IngestSyncResultOut>(`/api/cloud/accounts/${accountId}/sync`, { method: "POST" }),

  listContainerScans: () => request<ContainerScanOut[]>("/api/containers/scans"),
  createContainerScan: (body: ContainerScanCreateRequest) =>
    request<ContainerScanOut>("/api/containers/scans", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateContainerScan: (scanId: string, body: ContainerScanCreateRequest) =>
    request<ContainerScanOut>(`/api/containers/scans/${scanId}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  syncContainerScan: (scanId: string) =>
    request<IngestSyncResultOut>(`/api/containers/scans/${scanId}/sync`, { method: "POST" }),

  listRepoScans: () => request<RepoScanOut[]>("/api/repos/scans"),
  createRepoScan: (body: RepoScanCreateRequest) =>
    request<RepoScanOut>("/api/repos/scans", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateRepoScan: (scanId: string, body: RepoScanCreateRequest) =>
    request<RepoScanOut>(`/api/repos/scans/${scanId}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  syncRepoScan: (scanId: string) =>
    request<IngestSyncResultOut>(`/api/repos/scans/${scanId}/sync`, { method: "POST" }),

  listMobileScans: () => request<MobileScanOut[]>("/api/mobile/scans"),
  createMobileScan: (body: MobileScanCreateRequest) =>
    request<MobileScanOut>("/api/mobile/scans", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateMobileScan: (scanId: string, body: MobileScanCreateRequest) =>
    request<MobileScanOut>(`/api/mobile/scans/${scanId}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  syncMobileScan: (scanId: string) =>
    request<IngestSyncResultOut>(`/api/mobile/scans/${scanId}/sync`, { method: "POST" }),

  listAttackPaths: () => request<AttackPathOut[]>("/api/attack-paths"),

  listModuleToggles: () => request<ModuleToggleOut[]>("/api/module-toggles"),
  setModuleToggle: (moduleKey: ModuleKey, enabled: boolean) =>
    request<ModuleToggleOut>(`/api/module-toggles/${moduleKey}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled }),
    }),
};
