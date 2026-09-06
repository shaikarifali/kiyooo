"use client";

import { useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import type { ModuleKey } from "@/lib/types";
import { isModuleEnabled, useModuleToggles } from "@/lib/useModuleToggles";

/** Wraps a domain page's content — Cloud/Containers/Repos/Mobile/Attack
 * paths — with the "is this module turned on" check from the Settings
 * page. Turning a module off is a UI convenience only: it never touches
 * the API, CLI, or already-ingested data for that domain (see
 * kiyooo/api/routers/module_toggles.py), it just replaces the page body
 * with a one-click way back in. */
export function ModuleGate({
  moduleKey,
  label,
  children,
}: {
  moduleKey: ModuleKey;
  label: string;
  children: React.ReactNode;
}) {
  const { enabledMap, loading, refetch } = useModuleToggles();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (loading) return null;
  if (isModuleEnabled(enabledMap, moduleKey, loading)) return <>{children}</>;

  async function enable() {
    setBusy(true);
    setErr(null);
    try {
      await api.setModuleToggle(moduleKey, true);
      refetch();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h2>{label}</h2>
      <div className="card">
        <p className="muted">
          This module is turned off in <Link href="/settings">Settings</Link>. Nothing about the
          API, CLI, or any data already ingested for it changes — turning it back on just brings
          this page and its nav entry back.
        </p>
        <button disabled={busy} onClick={enable}>
          {busy ? "Enabling…" : `Enable ${label}`}
        </button>
        {err && <div className="error-box">{err}</div>}
      </div>
    </div>
  );
}
