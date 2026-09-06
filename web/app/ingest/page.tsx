"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type {
  AssetType,
  GenericRestConfig,
  IngestAuthType,
  IngestSourceOut,
  IngestSyncResultOut,
  UnmappedFindingOut,
} from "@/lib/types";

const ASSET_TYPES: AssetType[] = [
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
];

const AUTH_TYPES: { value: IngestAuthType; label: string }[] = [
  { value: "none", label: "None (public/internal API)" },
  { value: "bearer", label: "Bearer token" },
  { value: "header", label: "Custom header (API key, etc.)" },
  { value: "basic", label: "Basic auth" },
];

function emptyConfig(): GenericRestConfig {
  return {
    base_url: "",
    path: "",
    method: "GET",
    auth_type: "none",
    auth_header: "",
    auth_value_template: "",
    basic_username: "",
    credential_ref: "",
    items_path: "",
    field_mapping: {
      external_id: "",
      vendor_issue_type: "",
      title: "",
      vendor_severity: "",
      asset_value: "",
    },
    default_asset_type: "subdomain",
    since_param: "",
    next_cursor_path: "",
    cursor_param: "",
    max_pages: 20,
  };
}

export default function IngestPage() {
  const {
    data: sources,
    loading,
    error,
    refetch,
  } = useApi(() => api.listIngestSources(), []);
  const { data: unmapped, refetch: refetchUnmapped } = useApi(
    () => api.listUnmappedFindings(),
    [],
  );
  const [showAdd, setShowAdd] = useState(false);

  return (
    <div>
      <h2>Ingest</h2>
      <p className="muted">
        Point kiyooo at any REST/JSON-emitting ASM/VM tool your org already runs — Qualys, Wiz,
        or anything else that exposes a findings/issues API. No code change per tool: give it a
        URL, how to authenticate, and where in the vendor&apos;s JSON each field lives. We ingest
        their findings; we never inherit their severity — that always comes from our own category
        match, so every synced finding still goes through the same LLM adjudication (true/false
        positive, business justification) as everything else in kiyooo.
      </p>

      {error && <div className="error-box">{error}</div>}
      {loading && <p className="muted">Loading…</p>}

      {sources?.map((source) => (
        <SourceCard
          key={source.id}
          source={source}
          onChanged={() => {
            refetch();
            refetchUnmapped();
          }}
        />
      ))}

      <div className="card">
        <button className="secondary" onClick={() => setShowAdd((s) => !s)}>
          {showAdd ? "Cancel" : "Add a source"}
        </button>
        {showAdd && (
          <SourceForm
            initial={emptyConfig()}
            initialName=""
            onSaved={() => {
              setShowAdd(false);
              refetch();
            }}
          />
        )}
      </div>

      <h3 style={{ marginTop: 32 }}>Unmapped vendor issue types</h3>
      <p className="muted" style={{ marginTop: 0 }}>
        Ingested, but with no <code>vendor_mapping.yaml</code> entry (or no category applies) —
        a work item, not a silent drop.
      </p>
      <UnmappedTable rows={unmapped ?? []} />
    </div>
  );
}

function SourceCard({
  source,
  onChanged,
}: {
  source: IngestSourceOut;
  onChanged: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<IngestSyncResultOut | null>(null);
  const [syncErr, setSyncErr] = useState<string | null>(null);

  async function sync() {
    setSyncing(true);
    setSyncErr(null);
    setSyncResult(null);
    try {
      const result = await api.syncIngestSource(source.id);
      setSyncResult(result);
      onChanged();
    } catch (e) {
      setSyncErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setSyncing(false);
    }
  }

  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <h3 style={{ marginTop: 0, marginBottom: 4 }}>{source.name}</h3>
          <p className="muted" style={{ marginTop: 0, marginBottom: 4, fontSize: 13 }}>
            <code>
              {source.config.method} {source.config.base_url}
              {source.config.path}
            </code>
          </p>
          <p className="muted" style={{ marginTop: 0, fontSize: 12 }}>
            {source.last_sync_at
              ? `last synced ${new Date(source.last_sync_at).toLocaleString()}`
              : "never synced"}
          </p>
        </div>
        <span className={`badge ${source.enabled ? "low" : "info"}`}>
          {source.enabled ? "enabled" : "disabled"}
        </span>
      </div>

      <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
        <button disabled={syncing || !source.enabled} onClick={sync}>
          {syncing ? "Syncing…" : "Sync now"}
        </button>
        <button className="secondary" onClick={() => setEditing((e) => !e)}>
          {editing ? "Cancel" : "Edit"}
        </button>
      </div>

      {syncErr && <div className="error-box">{syncErr}</div>}
      {syncResult && (
        <p className="muted" style={{ marginTop: 8 }}>
          mapped: {syncResult.mapped} · unmapped: {syncResult.unmapped}
        </p>
      )}

      {editing && (
        <SourceForm
          sourceId={source.id}
          initial={source.config}
          initialName={source.name}
          initialEnabled={source.enabled}
          onSaved={() => {
            setEditing(false);
            onChanged();
          }}
        />
      )}
    </div>
  );
}

function SourceForm({
  sourceId,
  initial,
  initialName,
  initialEnabled = true,
  onSaved,
}: {
  sourceId?: string;
  initial: GenericRestConfig;
  initialName: string;
  initialEnabled?: boolean;
  onSaved: () => void;
}) {
  const [name, setName] = useState(initialName);
  const [config, setConfig] = useState<GenericRestConfig>(initial);
  const [enabled, setEnabled] = useState(initialEnabled);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);

  function set<K extends keyof GenericRestConfig>(key: K, value: GenericRestConfig[K]) {
    setConfig((c) => ({ ...c, [key]: value }));
  }
  function setField<K extends keyof GenericRestConfig["field_mapping"]>(key: K, value: string) {
    setConfig((c) => ({ ...c, field_mapping: { ...c.field_mapping, [key]: value } }));
  }

  const needsCredential = config.auth_type !== "none";

  async function testFetch() {
    setTesting(true);
    setTestResult(null);
    setErr(null);
    try {
      const result = await api.testIngestSource(config);
      if (!result.ok) {
        setErr(result.error ?? "test failed");
        return;
      }
      const sample = result.sample_titles.length
        ? ` — e.g. "${result.sample_titles[0]}"`
        : "";
      setTestResult(
        `fetched ${result.item_count} item(s) — would map: ${result.mapped_preview}, ` +
          `unmapped: ${result.unmapped_preview}${sample}`,
      );
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setTesting(false);
    }
  }

  async function submit() {
    if (!name.trim() || !config.base_url.trim() || !config.path.trim()) {
      setErr("Name, base URL, and path are all required.");
      return;
    }
    if (
      !config.field_mapping.external_id.trim() ||
      !config.field_mapping.asset_value.trim()
    ) {
      setErr("field_mapping.external_id and field_mapping.asset_value are required.");
      return;
    }
    if (needsCredential && !config.credential_ref?.trim()) {
      setErr(`auth_type '${config.auth_type}' needs a Credential env var.`);
      return;
    }
    if (config.auth_type === "header" && !(config.auth_header?.trim() && config.auth_value_template?.trim())) {
      setErr("auth_type 'header' needs both a header name and a value template.");
      return;
    }
    if (config.auth_type === "basic" && !config.basic_username?.trim()) {
      setErr("auth_type 'basic' needs a username.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const body = { name: name.trim(), config, enabled };
      if (sourceId) {
        await api.updateIngestSource(sourceId, body);
      } else {
        await api.createIngestSource(body);
      }
      onSaved();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid var(--border)" }}>
      <div className="filters">
        <input
          placeholder="Name — e.g. Prod Qualys tenant"
          value={name}
          onChange={(e) => setName(e.target.value)}
          style={{ width: 260 }}
        />
        <label>
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            style={{ marginRight: 4 }}
          />
          enabled
        </label>
      </div>

      <div className="filters">
        <input
          placeholder="Base URL — https://asm-tool.example.com"
          value={config.base_url}
          onChange={(e) => set("base_url", e.target.value)}
          style={{ width: 300 }}
        />
        <input
          placeholder="Path — /api/v1/issues"
          value={config.path}
          onChange={(e) => set("path", e.target.value)}
          style={{ width: 220 }}
        />
        <select value={config.method} onChange={(e) => set("method", e.target.value as "GET" | "POST")}>
          <option value="GET">GET</option>
          <option value="POST">POST</option>
        </select>
      </div>

      <div className="filters">
        <select
          value={config.auth_type}
          onChange={(e) => set("auth_type", e.target.value as IngestAuthType)}
        >
          {AUTH_TYPES.map((a) => (
            <option key={a.value} value={a.value}>
              {a.label}
            </option>
          ))}
        </select>
        {needsCredential && (
          <input
            placeholder="Credential env var — env:ASM_TOOL_API_KEY (never a raw key)"
            value={config.credential_ref ?? ""}
            onChange={(e) => set("credential_ref", e.target.value)}
            style={{ width: 320 }}
          />
        )}
      </div>

      {config.auth_type === "header" && (
        <div className="filters">
          <input
            placeholder="Header name — X-Api-Key"
            value={config.auth_header ?? ""}
            onChange={(e) => set("auth_header", e.target.value)}
            style={{ width: 200 }}
          />
          <input
            placeholder="Header value template — {credential} or ApiKey {credential}"
            value={config.auth_value_template ?? ""}
            onChange={(e) => set("auth_value_template", e.target.value)}
            style={{ width: 300 }}
          />
        </div>
      )}
      {config.auth_type === "basic" && (
        <div className="filters">
          <input
            placeholder="Basic auth username"
            value={config.basic_username ?? ""}
            onChange={(e) => set("basic_username", e.target.value)}
            style={{ width: 220 }}
          />
        </div>
      )}

      <p className="muted" style={{ marginTop: 12, marginBottom: 4, fontSize: 13 }}>
        Field mapping — dotted path into each vendor item&apos;s JSON (e.g. <code>plugin.id</code>
        for a nested field, <code>id</code> for a flat one):
      </p>
      <div className="filters">
        <input
          placeholder="Items path — data.issues (blank if the response body IS the list)"
          value={config.items_path ?? ""}
          onChange={(e) => set("items_path", e.target.value)}
          style={{ width: 320 }}
        />
        <select
          value={config.default_asset_type}
          onChange={(e) => set("default_asset_type", e.target.value as AssetType)}
        >
          {ASSET_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </div>
      <div className="filters">
        <input
          placeholder="external_id path — id"
          value={config.field_mapping.external_id}
          onChange={(e) => setField("external_id", e.target.value)}
          style={{ width: 160 }}
        />
        <input
          placeholder="vendor_issue_type path — issueType"
          value={config.field_mapping.vendor_issue_type}
          onChange={(e) => setField("vendor_issue_type", e.target.value)}
          style={{ width: 200 }}
        />
        <input
          placeholder="title path — title"
          value={config.field_mapping.title}
          onChange={(e) => setField("title", e.target.value)}
          style={{ width: 160 }}
        />
        <input
          placeholder="vendor_severity path — severity"
          value={config.field_mapping.vendor_severity}
          onChange={(e) => setField("vendor_severity", e.target.value)}
          style={{ width: 200 }}
        />
        <input
          placeholder="asset_value path — asset.hostname"
          value={config.field_mapping.asset_value}
          onChange={(e) => setField("asset_value", e.target.value)}
          style={{ width: 200 }}
        />
      </div>

      <button
        className="secondary"
        style={{ marginTop: 8 }}
        onClick={() => setShowAdvanced((s) => !s)}
      >
        {showAdvanced ? "Hide" : "Show"} advanced (pagination / incremental sync)
      </button>
      {showAdvanced && (
        <div className="filters" style={{ marginTop: 8 }}>
          <input
            placeholder="since_param — updated_since (kiyooo sends last sync's timestamp)"
            value={config.since_param ?? ""}
            onChange={(e) => set("since_param", e.target.value)}
            style={{ width: 260 }}
          />
          <input
            placeholder="next_cursor_path — meta.next_cursor"
            value={config.next_cursor_path ?? ""}
            onChange={(e) => set("next_cursor_path", e.target.value)}
            style={{ width: 220 }}
          />
          <input
            placeholder="cursor_param — cursor"
            value={config.cursor_param ?? ""}
            onChange={(e) => set("cursor_param", e.target.value)}
            style={{ width: 160 }}
          />
          <input
            type="number"
            min={1}
            max={200}
            value={config.max_pages ?? 20}
            onChange={(e) => set("max_pages", Number(e.target.value))}
            style={{ width: 100 }}
          />
        </div>
      )}

      <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
        <button disabled={busy} onClick={submit}>
          {busy ? "Saving…" : sourceId ? "Save changes" : "Add source"}
        </button>
        <button className="secondary" disabled={testing} onClick={testFetch}>
          {testing ? "Testing…" : "Test (run a real sync)"}
        </button>
      </div>

      {testResult && <p className="muted">{testResult}</p>}
      {err && <div className="error-box">{err}</div>}
    </div>
  );
}

function UnmappedTable({ rows }: { rows: UnmappedFindingOut[] }) {
  if (rows.length === 0) {
    return <p className="muted">Nothing unmapped right now.</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th>source</th>
          <th>external_id</th>
          <th>notes</th>
          <th>ingested_at</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.id}>
            <td>{r.source_name}</td>
            <td>{r.external_id}</td>
            <td>{r.mapping_notes}</td>
            <td>{new Date(r.ingested_at).toLocaleString()}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
