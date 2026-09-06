"use client";

import { useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import { ModuleGate } from "@/components/ModuleGate";
import { useApi } from "@/lib/useApi";
import type { IngestSyncResultOut, MobileScanConfig, MobileScanOut } from "@/lib/types";

function emptyConfig(): MobileScanConfig {
  return { platform: "android", apk_path: "" };
}

export default function MobilePage() {
  const { data: scans, loading, error, refetch } = useApi(() => api.listMobileScans(), []);
  const [showAdd, setShowAdd] = useState(false);

  return (
    <ModuleGate moduleKey="mobile" label="Mobile">
    <div>
      <h2>Mobile</h2>
      <p className="muted">
        Point kiyooo at a local Android APK for static analysis —{" "}
        <a href="https://apktool.org" target="_blank" rel="noreferrer">
          apktool
        </a>{" "}
        (open-source, Apache-2.0) decodes the manifest and resources, then a reused{" "}
        <Link href="/repos">TruffleHog</Link> filesystem scan checks the decoded smali/resources
        for verified live secrets. Strictly static: no device, emulator, or Frida involved
        anywhere, and no fetching apps from a store on your behalf — supply the APK file
        directly. Every finding still goes through the same category match and human review as
        everything else in kiyooo before reaching the <Link href="/triage">triage queue</Link>.
      </p>

      {error && <div className="error-box">{error}</div>}
      {loading && <p className="muted">Loading…</p>}

      {scans?.map((scan) => (
        <ScanCard key={scan.id} scan={scan} onChanged={refetch} />
      ))}

      <div className="card">
        <button className="secondary" onClick={() => setShowAdd((s) => !s)}>
          {showAdd ? "Cancel" : "Add an APK"}
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
        A Firebase database URL found in the app is a static signal only, not a confirmed-open
        database — confirming that would mean an active request to a third party&apos;s
        infrastructure, which this stage deliberately does not make. iOS/IPA isn&apos;t supported
        yet.
      </p>
    </div>
    </ModuleGate>
  );
}

function ScanCard({ scan, onChanged }: { scan: MobileScanOut; onChanged: () => void }) {
  const [editing, setEditing] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<IngestSyncResultOut | null>(null);
  const [syncErr, setSyncErr] = useState<string | null>(null);

  async function sync() {
    setSyncing(true);
    setSyncErr(null);
    setSyncResult(null);
    try {
      const result = await api.syncMobileScan(scan.id);
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
              {scan.config.platform} — {scan.config.apk_path}
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
  initial: MobileScanConfig;
  initialName?: string;
  initialEnabled?: boolean;
  onSaved: () => void;
}) {
  const [name, setName] = useState(initialName);
  const [config, setConfig] = useState<MobileScanConfig>(initial);
  const [enabled, setEnabled] = useState(initialEnabled);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit() {
    if (!name.trim() || !config.apk_path.trim()) {
      setErr("Name and APK path are both required.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const body = { name: name.trim(), config, enabled };
      if (scanId) {
        await api.updateMobileScan(scanId, body);
      } else {
        await api.createMobileScan(body);
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
          placeholder="Name — e.g. android-app-v2.3"
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
          placeholder="APK path on the kiyooo server — /data/apks/acmecorp-android-2.3.apk"
          value={config.apk_path}
          onChange={(e) => setConfig((c) => ({ ...c, apk_path: e.target.value }))}
          style={{ width: 460 }}
        />
      </div>

      <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
        <button disabled={busy} onClick={submit}>
          {busy ? "Saving…" : scanId ? "Save changes" : "Add APK"}
        </button>
      </div>

      {err && <div className="error-box">{err}</div>}
    </div>
  );
}
