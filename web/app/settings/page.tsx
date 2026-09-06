"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { ModuleKey, ModuleToggleOut } from "@/lib/types";
import { useModuleToggles } from "@/lib/useModuleToggles";

const MODULE_INFO: Record<ModuleKey, { label: string; description: string; href: string }> = {
  cloud: {
    label: "Cloud posture",
    description: "AWS/Azure/GCP/Kubernetes account audits via Prowler.",
    href: "/cloud",
  },
  containers: {
    label: "Containers & Kubernetes",
    description: "Image and cluster scanning via Trivy.",
    href: "/containers",
  },
  repos: {
    label: "Source code & supply chain",
    description: "Verified live-secret scanning via TruffleHog.",
    href: "/repos",
  },
  mobile: {
    label: "Mobile",
    description: "Static Android APK analysis via apktool + TruffleHog.",
    href: "/mobile",
  },
  attack_paths: {
    label: "Attack paths",
    description: "Correlated chains from a weakness to a sensitive resource.",
    href: "/attack-paths",
  },
};

export default function SettingsPage() {
  const { toggles, loading, error, refetch } = useModuleToggles();

  return (
    <div>
      <h2>Settings</h2>
      <p className="muted">
        Turn optional attack-surface modules on or off. This only controls what shows up in the
        nav and on each module&apos;s page — it never touches the API, CLI, or any data already
        ingested for a module you turn off, so re-enabling one loses nothing.
      </p>

      {error && <div className="error-box">{error}</div>}
      {loading && <p className="muted">Loading…</p>}

      {toggles?.map((toggle) => (
        <ModuleRow key={toggle.module_key} toggle={toggle} onChanged={refetch} />
      ))}
    </div>
  );
}

function ModuleRow({ toggle, onChanged }: { toggle: ModuleToggleOut; onChanged: () => void }) {
  const info = MODULE_INFO[toggle.module_key];
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function toggleEnabled() {
    setBusy(true);
    setErr(null);
    try {
      await api.setModuleToggle(toggle.module_key, !toggle.enabled);
      onChanged();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h3 style={{ marginTop: 0, marginBottom: 4 }}>{info?.label ?? toggle.module_key}</h3>
          <p className="muted" style={{ marginTop: 0, fontSize: 13 }}>
            {info?.description}
          </p>
        </div>
        <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
          <span className={`badge ${toggle.enabled ? "low" : "info"}`}>
            {toggle.enabled ? "on" : "off"}
          </span>
          <input
            type="checkbox"
            checked={toggle.enabled}
            disabled={busy}
            onChange={toggleEnabled}
          />
        </label>
      </div>
      {err && <div className="error-box">{err}</div>}
    </div>
  );
}
