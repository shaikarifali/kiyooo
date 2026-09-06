"use client";

import { useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import { ModuleGate } from "@/components/ModuleGate";
import { useApi } from "@/lib/useApi";
import type { CloudAccountOut, CloudProvider, IngestSyncResultOut, ProwlerConfig } from "@/lib/types";

const PROVIDERS: { value: CloudProvider; label: string }[] = [
  { value: "aws", label: "AWS" },
  { value: "azure", label: "Azure" },
  { value: "gcp", label: "GCP" },
  { value: "kubernetes", label: "Kubernetes" },
];

function emptyConfig(): ProwlerConfig {
  return { provider: "aws", credential_env: {}, extra_args: [] };
}

export default function CloudPage() {
  const { data: accounts, loading, error, refetch } = useApi(() => api.listCloudAccounts(), []);
  const [showAdd, setShowAdd] = useState(false);

  return (
    <ModuleGate moduleKey="cloud" label="Cloud posture">
    <div>
      <h2>Cloud posture</h2>
      <p className="muted">
        Point kiyooo at an AWS, Azure, GCP, or Kubernetes account and audit it with{" "}
        <a href="https://github.com/prowler-cloud/prowler" target="_blank" rel="noreferrer">
          Prowler
        </a>{" "}
        (open-source, Apache-2.0) — public buckets, wide-open security groups, wildcard IAM
        policies, and more. A raw Prowler hit is a candidate, never a finding shown to you on its
        own: every one still goes through the same category match and LLM adjudication (true/false
        positive, business justification) as everything else in kiyooo before it reaches the{" "}
        <Link href="/triage">triage queue</Link>.
      </p>

      {error && <div className="error-box">{error}</div>}
      {loading && <p className="muted">Loading…</p>}

      {accounts?.map((account) => (
        <AccountCard key={account.id} account={account} onChanged={refetch} />
      ))}

      <div className="card">
        <button className="secondary" onClick={() => setShowAdd((s) => !s)}>
          {showAdd ? "Cancel" : "Add a cloud account"}
        </button>
        {showAdd && (
          <AccountForm
            initial={emptyConfig()}
            onSaved={() => {
              setShowAdd(false);
              refetch();
            }}
          />
        )}
      </div>

      <p className="muted" style={{ marginTop: 24 }}>
        A Prowler check with no <code>vendor_mapping.yaml</code> entry yet shows up in the{" "}
        <Link href="/ingest">Ingest page&apos;s unmapped table</Link> — same gap-visibility
        guarantee as any other source, never a silent drop.
      </p>
    </div>
    </ModuleGate>
  );
}

function AccountCard({
  account,
  onChanged,
}: {
  account: CloudAccountOut;
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
      const result = await api.syncCloudAccount(account.id);
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
          <h3 style={{ marginTop: 0, marginBottom: 4 }}>{account.name}</h3>
          <p className="muted" style={{ marginTop: 0, marginBottom: 4, fontSize: 13 }}>
            <code>{account.config.provider}</code>
          </p>
          <p className="muted" style={{ marginTop: 0, fontSize: 12 }}>
            {account.last_sync_at
              ? `last audited ${new Date(account.last_sync_at).toLocaleString()}`
              : "never audited"}
          </p>
        </div>
        <span className={`badge ${account.enabled ? "low" : "info"}`}>
          {account.enabled ? "enabled" : "disabled"}
        </span>
      </div>

      <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
        <button disabled={syncing || !account.enabled} onClick={sync}>
          {syncing ? "Auditing… (this runs a full Prowler scan)" : "Audit now"}
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
        <AccountForm
          accountId={account.id}
          initial={account.config}
          initialName={account.name}
          initialEnabled={account.enabled}
          onSaved={() => {
            setEditing(false);
            onChanged();
          }}
        />
      )}
    </div>
  );
}

function AccountForm({
  accountId,
  initial,
  initialName = "",
  initialEnabled = true,
  onSaved,
}: {
  accountId?: string;
  initial: ProwlerConfig;
  initialName?: string;
  initialEnabled?: boolean;
  onSaved: () => void;
}) {
  const [name, setName] = useState(initialName);
  const [config, setConfig] = useState<ProwlerConfig>(initial);
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
      if (accountId) {
        await api.updateCloudAccount(accountId, body);
      } else {
        await api.createCloudAccount(body);
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
          placeholder="Name — e.g. prod-aws"
          value={name}
          onChange={(e) => setName(e.target.value)}
          style={{ width: 260 }}
        />
        <select
          value={config.provider}
          onChange={(e) => setConfig((c) => ({ ...c, provider: e.target.value as CloudProvider }))}
        >
          {PROVIDERS.map((p) => (
            <option key={p.value} value={p.value}>
              {p.label}
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

      <p className="muted" style={{ marginTop: 12, marginBottom: 4, fontSize: 13 }}>
        Credential env vars — whatever your provider&apos;s SDK/Prowler itself expects (e.g.{" "}
        <code>AWS_ACCESS_KEY_ID</code>, <code>GOOGLE_APPLICATION_CREDENTIALS</code>). Each value is
        a <code>credential_ref</code> pointer (<code>env:VAR_NAME</code>), never a raw secret.
      </p>
      {envRows.map((row, i) => (
        <div className="filters" key={i}>
          <input
            placeholder="Env var name — AWS_ACCESS_KEY_ID"
            value={row.key}
            onChange={(e) => setEnvRow(i, "key", e.target.value)}
            style={{ width: 240 }}
          />
          <input
            placeholder="credential_ref — env:PROD_AWS_ACCESS_KEY_ID"
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
        Extra Prowler CLI flags (space-separated) — <code>--profile</code>,{" "}
        <code>--role-arn</code>, <code>--subscription-ids</code>, etc. Leave blank if the env vars
        above are enough.
      </p>
      <input
        placeholder="--profile prod"
        value={extraArgsText}
        onChange={(e) => setExtraArgsText(e.target.value)}
        style={{ width: 400 }}
      />

      <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
        <button disabled={busy} onClick={submit}>
          {busy ? "Saving…" : accountId ? "Save changes" : "Add cloud account"}
        </button>
      </div>

      {err && <div className="error-box">{err}</div>}
    </div>
  );
}
