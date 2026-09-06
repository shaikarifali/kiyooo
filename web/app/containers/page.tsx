"use client";

import { useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import { ModuleGate } from "@/components/ModuleGate";
import { useApi } from "@/lib/useApi";
import type {
  ContainerScanOut,
  IngestSyncResultOut,
  TrivyConfig,
  TrivyScanKind,
} from "@/lib/types";

const SCAN_KINDS: { value: TrivyScanKind; label: string }[] = [
  { value: "image", label: "Container image" },
  { value: "k8s", label: "Kubernetes cluster" },
];

function emptyConfig(): TrivyConfig {
  return { scan_kind: "image", target: "", credential_env: {}, extra_args: [] };
}

export default function ContainersPage() {
  const { data: scans, loading, error, refetch } = useApi(() => api.listContainerScans(), []);
  const [showAdd, setShowAdd] = useState(false);

  return (
    <ModuleGate moduleKey="containers" label="Containers & Kubernetes">
    <div>
      <h2>Containers &amp; Kubernetes</h2>
      <p className="muted">
        Point kiyooo at a container image or a Kubernetes cluster and scan it with{" "}
        <a href="https://github.com/aquasecurity/trivy" target="_blank" rel="noreferrer">
          Trivy
        </a>{" "}
        (open-source, Apache-2.0) — vulnerable packages, privileged/root containers,
        overly-permissive RBAC, and missing network policies. Same rule as everywhere else in
        kiyooo: a raw Trivy hit is a candidate, never a finding shown to you on its own — every one
        goes through the same category match and LLM adjudication before it reaches the{" "}
        <Link href="/triage">triage queue</Link>.
      </p>

      {error && <div className="error-box">{error}</div>}
      {loading && <p className="muted">Loading…</p>}

      {scans?.map((scan) => (
        <ScanCard key={scan.id} scan={scan} onChanged={refetch} />
      ))}

      <div className="card">
        <button className="secondary" onClick={() => setShowAdd((s) => !s)}>
          {showAdd ? "Cancel" : "Add a scan"}
        </button>
        {showAdd && (
          <ScanForm
            initial={emptyConfig()}
            onSaved={() => {
              setShowAdd(false);
              refetch();
            }}
          />
        )}
      </div>

      <p className="muted" style={{ marginTop: 24 }}>
        A Trivy misconfiguration check with no <code>vendor_mapping.yaml</code> entry yet shows up
        in the <Link href="/ingest">Ingest page&apos;s unmapped table</Link>. Every CVE Trivy
        reports lands in one <code>vulnerable-base-image</code> category regardless of which CVE —
        the specific package/version/fix is carried as evidence for the LLM to reason about, not
        encoded per-CVE in our own category list.
      </p>
    </div>
    </ModuleGate>
  );
}

function ScanCard({ scan, onChanged }: { scan: ContainerScanOut; onChanged: () => void }) {
  const [editing, setEditing] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<IngestSyncResultOut | null>(null);
  const [syncErr, setSyncErr] = useState<string | null>(null);

  async function sync() {
    setSyncing(true);
    setSyncErr(null);
    setSyncResult(null);
    try {
      const result = await api.syncContainerScan(scan.id);
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
          <h3 style={{ marginTop: 0, marginBottom: 4 }}>{scan.name}</h3>
          <p className="muted" style={{ marginTop: 0, marginBottom: 4, fontSize: 13 }}>
            <code>
              {scan.config.scan_kind}
              {scan.config.target ? ` — ${scan.config.target}` : ""}
            </code>
          </p>
          <p className="muted" style={{ marginTop: 0, fontSize: 12 }}>
            {scan.last_sync_at
              ? `last scanned ${new Date(scan.last_sync_at).toLocaleString()}`
              : "never scanned"}
          </p>
        </div>
        <span className={`badge ${scan.enabled ? "low" : "info"}`}>
          {scan.enabled ? "enabled" : "disabled"}
        </span>
      </div>

      <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
        <button disabled={syncing || !scan.enabled} onClick={sync}>
          {syncing ? "Scanning…" : "Scan now"}
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
        <ScanForm
          scanId={scan.id}
          initial={scan.config}
          initialName={scan.name}
          initialEnabled={scan.enabled}
          onSaved={() => {
            setEditing(false);
            onChanged();
          }}
        />
      )}
    </div>
  );
}

function ScanForm({
  scanId,
  initial,
  initialName = "",
  initialEnabled = true,
  onSaved,
}: {
  scanId?: string;
  initial: TrivyConfig;
  initialName?: string;
  initialEnabled?: boolean;
  onSaved: () => void;
}) {
  const [name, setName] = useState(initialName);
  const [config, setConfig] = useState<TrivyConfig>(initial);
  const [enabled, setEnabled] = useState(initialEnabled);
  const [envRows, setEnvRows] = useState<{ key: string; ref: string }[]>(
    Object.entries(initial.credential_env).length
      ? Object.entries(initial.credential_env).map(([key, ref]) => ({ key, ref }))
      : [{ key: "", ref: "" }],
  );
  const [extraArgsText, setExtraArgsText] = useState(initial.extra_args.join(" "));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  function setEnvRow(i: number, field: "key" | "ref", value: string) {
    setEnvRows((rows) => rows.map((r, idx) => (idx === i ? { ...r, [field]: value } : r)));
  }

  async function submit() {
    if (!name.trim()) {
      setErr("Name is required.");
      return;
    }
    if (config.scan_kind === "image" && !config.target.trim()) {
      setErr("An image scan needs a target — the image reference (e.g. nginx:1.25).");
      return;
    }
    const credential_env: Record<string, string> = {};
    for (const row of envRows) {
      if (row.key.trim()) credential_env[row.key.trim()] = row.ref.trim();
    }
    const extra_args = extraArgsText
      .split(" ")
      .map((s) => s.trim())
      .filter(Boolean);

    setBusy(true);
    setErr(null);
    try {
      const body = { name: name.trim(), config: { ...config, credential_env, extra_args }, enabled };
      if (scanId) {
        await api.updateContainerScan(scanId, body);
      } else {
        await api.createContainerScan(body);
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
          placeholder="Name — e.g. web-app-image or prod-cluster"
          value={name}
          onChange={(e) => setName(e.target.value)}
          style={{ width: 260 }}
        />
        <select
          value={config.scan_kind}
          onChange={(e) =>
            setConfig((c) => ({ ...c, scan_kind: e.target.value as TrivyScanKind }))
          }
        >
          {SCAN_KINDS.map((k) => (
            <option key={k.value} value={k.value}>
              {k.label}
            </option>
          ))}
        </select>
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
          placeholder={
            config.scan_kind === "image"
              ? "Image reference — registry.example.com/web-app:1.4.2"
              : "kubeconfig context name (blank = current context)"
          }
          value={config.target}
          onChange={(e) => setConfig((c) => ({ ...c, target: e.target.value }))}
          style={{ width: 380 }}
        />
      </div>

      <p className="muted" style={{ marginTop: 12, marginBottom: 4, fontSize: 13 }}>
        Credential env vars — a private registry&apos;s auth vars for an image scan, or{" "}
        <code>KUBECONFIG</code> (pointing at a file path) for a cluster scan. Each value is a{" "}
        <code>credential_ref</code> pointer (<code>env:VAR_NAME</code>), never a raw secret.
      </p>
      {envRows.map((row, i) => (
        <div className="filters" key={i}>
          <input
            placeholder="Env var name — KUBECONFIG"
            value={row.key}
            onChange={(e) => setEnvRow(i, "key", e.target.value)}
            style={{ width: 240 }}
          />
          <input
            placeholder="credential_ref — env:PROD_KUBECONFIG_PATH"
            value={row.ref}
            onChange={(e) => setEnvRow(i, "ref", e.target.value)}
            style={{ width: 320 }}
          />
        </div>
      ))}
      <button
        className="secondary"
        style={{ marginTop: 4 }}
        onClick={() => setEnvRows((rows) => [...rows, { key: "", ref: "" }])}
      >
        + add another env var
      </button>

      <p className="muted" style={{ marginTop: 12, marginBottom: 4, fontSize: 13 }}>
        Extra Trivy CLI flags (space-separated) — <code>--severity</code>,{" "}
        <code>--ignore-unfixed</code>, etc. Leave blank for Trivy&apos;s defaults.
      </p>
      <input
        placeholder="--severity CRITICAL,HIGH"
        value={extraArgsText}
        onChange={(e) => setExtraArgsText(e.target.value)}
        style={{ width: 400 }}
      />

      <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
        <button disabled={busy} onClick={submit}>
          {busy ? "Saving…" : scanId ? "Save changes" : "Add scan"}
        </button>
      </div>

      {err && <div className="error-box">{err}</div>}
    </div>
  );
}
