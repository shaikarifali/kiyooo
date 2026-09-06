"use client";

import Link from "next/link";
import { api } from "@/lib/api";
import { ModuleGate } from "@/components/ModuleGate";
import { useApi } from "@/lib/useApi";
import type { AttackPathHopOut, AttackPathOut } from "@/lib/types";

export default function AttackPathsPage() {
  const { data: paths, loading, error } = useApi(() => api.listAttackPaths(), []);

  return (
    <ModuleGate moduleKey="attack_paths" label="Attack paths">
    <div>
      <h2>Attack paths</h2>
      <p className="muted">
        One correlated path instead of N unrelated findings — each of these connects an ordinary
        weakness to a resource that holds or grants access to data or credentials (a database, an
        object store, a leaked credential), via the shortest chain of asset relationships between
        them. Computed live from the current asset graph and{" "}
        <Link href="/triage">active findings</Link>, not a stored/stale list.
      </p>

      {error && <div className="error-box">{error}</div>}
      {loading && <p className="muted">Loading…</p>}

      {paths && paths.length === 0 && (
        <p className="muted">
          No attack paths found — either nothing in the graph connects two active findings yet, or
          no category is marked <code>is_sensitive_target</code> in org-context.
        </p>
      )}

      {paths?.map((path, i) => <PathCard key={i} path={path} />)}
    </div>
    </ModuleGate>
  );
}

function PathCard({ path }: { path: AttackPathOut }) {
  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h3 style={{ marginTop: 0, marginBottom: 4 }}>
          Path to <code>{path.sensitive_category_id}</code>
        </h3>
        <span className="muted" style={{ fontSize: 13 }}>
          score: {path.score.toFixed(2)}
        </span>
      </div>

      <div style={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: 8, marginTop: 8 }}>
        {path.hops.map((hop, i) => (
          <div key={hop.asset_id} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <HopChip hop={hop} />
            {i < path.hops.length - 1 && <span className="muted">→</span>}
          </div>
        ))}
      </div>
    </div>
  );
}

function HopChip({ hop }: { hop: AttackPathHopOut }) {
  return (
    <div
      style={{
        border: "1px solid var(--border)",
        borderRadius: 6,
        padding: "6px 10px",
        minWidth: 160,
      }}
    >
      <div className="muted" style={{ fontSize: 11 }}>
        {hop.asset_type}
      </div>
      <div style={{ fontSize: 13, fontFamily: "monospace", wordBreak: "break-all" }}>
        {hop.asset_value}
      </div>
      {hop.finding_category_id && (
        <div style={{ marginTop: 4 }}>
          <span className={`badge ${hop.finding_severity ?? "info"}`}>
            {hop.finding_category_id}
          </span>
        </div>
      )}
    </div>
  );
}
