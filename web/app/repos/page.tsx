"use client";

import { useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import { ModuleGate } from "@/components/ModuleGate";
import { useApi } from "@/lib/useApi";
import type { IngestSyncResultOut, RepoScanOut, TrufflehogConfig } from "@/lib/types";

function emptyConfig(): TrufflehogConfig {
  return { repo_url: "", credential_ref: "", extra_args: [] };
}

export default function ReposPage() {
  const { data: scans, loading, error, refetch } = useApi(() => api.listRepoScans(), []);
  const [showAdd, setShowAdd] = useState(false);

  return (
    <ModuleGate moduleKey="repos" label="Source code & supply chain">
    <div>
      <h2>Source code &amp; supply chain</h2>
      <p className="muted">
        Point kiyooo at a git repo and scan it for verified live secrets with{" "}
        <a href="https://github.com/trufflesecurity/trufflehog" target="_blank" rel="noreferrer">
          TruffleHog
        </a>{" "}
        (open-source engine, AGPL-3.0). TruffleHog only reports a finding after confirming the
        credential still works against its actual provider (AWS, GitHub, Stripe, etc.) — an
        already-rotated key never becomes a candidate finding at all. Every verified secret still
        goes through the same category match and human review as everything else in kiyooo before
        reaching the <Link href="/triage">triage queue</Link>, and is flagged{" "}
        <code>local_only</code> so it&apos;s never sent to a hosted LLM provider.
      </p>

      {error && <div className="error-box">{error}</div>}
      {loading && <p className="muted">Loading…</p>}

      {scans?.map((scan) => (
        <ScanCard key={scan.id} scan={scan} onChanged={refetch} />
      ))}

      <div className="card">
        <button className="secondary" onClick={() => setShowAdd((s) => !s)}>
          {showAdd ? "Cancel" : "Add a repo"}
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
        There&apos;s no &quot;scan every repo in this org&quot; auto-discovery yet — GitHub,
        GitLab, Gitea, and Forgejo all paginate their repo-listing APIs differently. List the repos
        that matter explicitly for now.
      </p>
    </div>
    </ModuleGate>
  );
}

function ScanCard({ scan, onChanged }: { scan: RepoScanOut; onChanged: () => void }) {
  const [editing, setEditing] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<IngestSyncResultOut | null>(null);
  const [syncErr, setSyncErr] = useState<string | null>(null);

  async function sync() {
    setSyncing(true);
    setSyncErr(null);
    setSyncResult(null);
    try {
      const result = await api.syncRepoScan(scan.id);
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
            <code>{scan.config.repo_url}</code>
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
  initial: TrufflehogConfig;
  initialName?: string;
  initialEnabled?: boolean;
  onSaved: () => void;
}) {
  const [name, setName] = useState(initialName);
  const [config, setConfig] = useState<TrufflehogConfig>(initial);
  const [enabled, setEnabled] = useState(initialEnabled);
  const [extraArgsText, setExtraArgsText] = useState(initial.extra_args.join(" "));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit() {
    if (!name.trim() || !config.repo_url.trim()) {
      setErr("Name and repo URL are both required.");
      return;
    }
    const extra_args = extraArgsText
      .split(" ")
      .map((s) => s.trim())
      .filter(Boolean);

    setBusy(true);
    setErr(null);
    try {
      const body = {
        name: name.trim(),
        config: {
          ...config,
          credential_ref: config.credential_ref?.trim() || null,
          extra_args,
        },
        enabled,
      };
      if (scanId) {
        await api.updateRepoScan(scanId, body);
      } else {
        await api.createRepoScan(body);
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
          placeholder="Name — e.g. internal-api-repo"
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
          placeholder="Repo URL — https://github.com/acmecorp/internal-api.git"
          value={config.repo_url}
          onChange={(e) => setConfig((c) => ({ ...c, repo_url: e.target.value }))}
          style={{ width: 420 }}
        />
      </div>

      <p className="muted" style={{ marginTop: 12, marginBottom: 4, fontSize: 13 }}>
        For a private repo, put a <code>{"{credential}"}</code> placeholder in the URL (e.g.{" "}
        <code>https://{"{credential}"}@github.com/org/repo.git</code>) and point{" "}
        <code>credential_ref</code> at the env var holding the token. A public repo needs neither.
      </p>
      <div className="filters">
        <input
          placeholder="credential_ref — env:GITHUB_REPO_SCAN_TOKEN"
          value={config.credential_ref ?? ""}
          onChange={(e) => setConfig((c) => ({ ...c, credential_ref: e.target.value }))}
          style={{ width: 320 }}
        />
      </div>

      <p className="muted" style={{ marginTop: 12, marginBottom: 4, fontSize: 13 }}>
        Extra TruffleHog CLI flags (space-separated) — <code>--branch</code>,{" "}
        <code>--since-commit</code>, etc. Leave blank for TruffleHog&apos;s defaults (full history).
      </p>
      <input
        placeholder="--branch main"
        value={extraArgsText}
        onChange={(e) => setExtraArgsText(e.target.value)}
        style={{ width: 400 }}
      />

      <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
        <button disabled={busy} onClick={submit}>
          {busy ? "Saving…" : scanId ? "Save changes" : "Add repo"}
        </button>
      </div>

      {err && <div className="error-box">{err}</div>}
    </div>
  );
}
