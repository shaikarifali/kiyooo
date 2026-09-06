"use client";

import { useMemo, useState } from "react";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { OwnerType } from "@/lib/types";

type PickerEntry = { kind: OwnerType; ref: string; label: string };

/** Bulk-assign an owner across every selected finding's underlying asset.
 * Findings don't carry ownership directly — assets do — so this resolves
 * the unique asset ids behind the selection and writes the same MANUAL
 * ownership override `POST /api/assets/{id}/ownership` already does, once
 * per asset. Sequential, not parallel: a human is confirming an
 * assignment they're about to see reflected finding-by-finding, and a
 * partial-failure summary needs to be attributable per asset, not a
 * single opaque Promise.all rejection.
 */
export function AssignOwnerModal({
  assetIds,
  findingCount,
  reviewer,
  onClose,
  onDone,
}: {
  assetIds: string[];
  findingCount: number;
  reviewer: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const { data: teams } = useApi(() => api.listTeams(), []);
  const [tab, setTab] = useState<"any" | "user" | "team">("any");
  const [query, setQuery] = useState("");
  const [picked, setPicked] = useState<PickerEntry | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<{ ok: number; failed: number } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  // Only IDs still owed a successful assign — shrinks to just the failures
  // after a partial-failure attempt, so clicking "retry" doesn't re-POST
  // (and re-audit-log) the ones that already succeeded.
  const [pendingAssetIds, setPendingAssetIds] = useState<string[]>(assetIds);

  const entries = useMemo<PickerEntry[]>(() => {
    if (!teams) return [];
    const teamEntries: PickerEntry[] = teams.map((t) => ({
      kind: "team",
      ref: t.id,
      label: t.slack ? `${t.id} (${t.slack})` : t.id,
    }));
    const seen = new Set<string>();
    const userEntries: PickerEntry[] = [];
    for (const t of teams) {
      for (const member of t.members) {
        if (seen.has(member)) continue;
        seen.add(member);
        userEntries.push({ kind: "user", ref: member, label: member });
      }
    }
    const pool = tab === "user" ? userEntries : tab === "team" ? teamEntries : [...userEntries, ...teamEntries];
    const q = query.trim().toLowerCase();
    return q ? pool.filter((e) => e.label.toLowerCase().includes(q)) : pool;
  }, [teams, tab, query]);

  async function assign() {
    if (!picked || !reviewer.trim()) {
      setErr("Pick an owner and enter your reviewer email first.");
      return;
    }
    setSubmitting(true);
    setErr(null);
    let ok = 0;
    const stillFailed: string[] = [];
    for (const assetId of pendingAssetIds) {
      try {
        await api.overrideOwnership(assetId, {
          owner_type: picked.kind,
          owner_ref: picked.ref,
          reviewer,
          note: `bulk-assigned across ${findingCount} finding(s)`,
        });
        ok++;
      } catch {
        stillFailed.push(assetId);
      }
    }
    setSubmitting(false);
    setPendingAssetIds(stillFailed);
    setResult({ ok, failed: stillFailed.length });
    if (stillFailed.length === 0) onDone();
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h3>Assign owner</h3>
          <button className="modal-close" onClick={onClose}>
            ×
          </button>
        </div>

        <div className="modal-summary">
          <span className="n">{findingCount}</span> selected finding
          {findingCount === 1 ? "" : "s"} across <span className="n">{assetIds.length}</span> asset
          {assetIds.length === 1 ? "" : "s"}
          {pendingAssetIds.length !== assetIds.length && (
            <>
              {" "}
              — <span className="n">{pendingAssetIds.length}</span> still pending
            </>
          )}
          {picked && (
            <>
              <br />
              assigning to: <strong>{picked.label}</strong> ({picked.kind})
            </>
          )}
        </div>

        <div className="tab-row">
          {(["any", "user", "team"] as const).map((t) => (
            <button
              key={t}
              className={tab === t ? "active" : ""}
              onClick={() => setTab(t)}
            >
              {t === "any" ? "Any" : t === "user" ? "Users" : "Teams"}
            </button>
          ))}
        </div>

        <input
          placeholder="Search by user or team"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ width: "100%", marginBottom: 10 }}
        />

        <div className="picker-list">
          {entries.length === 0 && <p className="picker-empty muted">No match.</p>}
          {entries.map((e) => (
            <div
              key={`${e.kind}:${e.ref}`}
              className={`picker-row ${picked?.ref === e.ref && picked?.kind === e.kind ? "selected" : ""}`}
              onClick={() => setPicked(e)}
            >
              <span>{e.label}</span>
              <span className="kind">{e.kind}</span>
            </div>
          ))}
        </div>

        {err && <div className="error-box">{err}</div>}
        {result && (
          <p className={result.failed ? "error-box" : "muted"} style={{ marginTop: 4 }}>
            {result.ok} assigned
            {result.failed
              ? `, ${result.failed} failed — Retry only resubmits those.`
              : "."}
          </p>
        )}

        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <button className="secondary" onClick={onClose}>
            {result && !result.failed ? "Close" : "Cancel"}
          </button>
          <button
            disabled={submitting || !picked || pendingAssetIds.length === 0}
            onClick={assign}
          >
            {submitting
              ? "Assigning…"
              : result && result.failed > 0
                ? `Retry ${pendingAssetIds.length}`
                : "Assign"}
          </button>
        </div>
      </div>
    </div>
  );
}
