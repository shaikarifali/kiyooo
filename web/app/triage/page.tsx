"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { SeverityBadge } from "@/components/SeverityBadge";
import { AssignOwnerModal } from "@/components/AssignOwnerModal";
import { BulkResolutionModal } from "@/components/BulkResolutionModal";
import { downloadCsv } from "@/lib/csv";
import type { FindingStatus } from "@/lib/types";

const STATUSES: FindingStatus[] = [
  "triaged",
  "new",
  "triaging",
  "routed",
  "verification_pending",
  "regressed",
];

export default function TriageQueuePage() {
  const [status, setStatus] = useState<FindingStatus>("triaged");
  const { data, loading, error, refetch } = useApi(
    () => api.listFindings({ status, limit: 200 }),
    [status],
  );

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [reviewer, setReviewer] = useState("");
  const [modal, setModal] = useState<"owner" | "resolution" | null>(null);

  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  function toggleAll() {
    if (!data) return;
    setSelected((prev) => (prev.size === data.length ? new Set() : new Set(data.map((f) => f.id))));
  }

  function clearSelection() {
    setSelected(new Set());
  }

  function closeModal() {
    setModal(null);
  }

  function onBulkDone() {
    clearSelection();
    setModal(null);
    refetch();
  }

  function exportCsv() {
    if (!data) return;
    downloadCsv(
      `triage-${status}.csv`,
      data.map((f) => ({
        id: f.id,
        severity: f.raw_severity,
        category_id: f.category_id,
        title: f.title,
        detector: f.detector,
        status: f.status,
        last_seen: f.last_seen,
        asset_id: f.asset_id,
        scan_run_id: f.scan_run_id,
      })),
    );
  }

  const selectedAssetIds = useMemo(() => {
    if (!data) return [];
    const ids = new Set<string>();
    for (const f of data) {
      if (selected.has(f.id)) ids.add(f.asset_id);
    }
    return [...ids];
  }, [data, selected]);

  return (
    <div>
      <h2>Triage queue</h2>
      <p className="muted">
        Finding + verdict + reasoning + evidence, agree/disagree in one click (the design Stage
        10). Select rows to assign an owner or resolve several findings at once.
      </p>

      <div className="filters">
        <label>
          Status:
          <select
            value={status}
            onChange={(e) => {
              setStatus(e.target.value as FindingStatus);
              clearSelection();
            }}
            style={{ marginLeft: 8 }}
          >
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label style={{ marginLeft: "auto" }}>
          Reviewer:
          <input
            placeholder="you@example.com"
            value={reviewer}
            onChange={(e) => setReviewer(e.target.value)}
            style={{ marginLeft: 8, width: 220 }}
          />
        </label>
        <button className="secondary" disabled={!data || data.length === 0} onClick={exportCsv}>
          Export CSV
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}
      {loading && <p className="muted">Loading…</p>}

      {data && (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th className="row-checkbox">
                  <input
                    type="checkbox"
                    checked={data.length > 0 && selected.size === data.length}
                    onChange={toggleAll}
                    aria-label="select all"
                  />
                </th>
                <th>Severity</th>
                <th>Category</th>
                <th>Title</th>
                <th>Detector</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {data.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    Nothing here.
                  </td>
                </tr>
              )}
              {data.map((finding) => (
                <tr key={finding.id}>
                  <td className="row-checkbox">
                    <input
                      type="checkbox"
                      checked={selected.has(finding.id)}
                      onChange={() => toggle(finding.id)}
                      aria-label={`select ${finding.title}`}
                    />
                  </td>
                  <td>
                    <SeverityBadge severity={finding.raw_severity} />
                  </td>
                  <td>{finding.category_id}</td>
                  <td>
                    <Link href={`/triage/${finding.id}`}>{finding.title}</Link>
                  </td>
                  <td>{finding.detector}</td>
                  <td>{new Date(finding.last_seen).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected.size > 0 && (
        <div className="bulk-bar">
          <div>
            <span className="count">{selected.size}</span> of {data?.length ?? 0} rows selected
            {"  "}
            <button className="clear" onClick={clearSelection}>
              Clear selection
            </button>
          </div>
          <div className="actions">
            <button
              className="secondary"
              disabled={!reviewer.trim()}
              title={reviewer.trim() ? "" : "enter a reviewer email above first"}
              onClick={() => setModal("owner")}
            >
              Assign Owner
            </button>
            <button
              className="secondary"
              disabled={!reviewer.trim()}
              title={reviewer.trim() ? "" : "enter a reviewer email above first"}
              onClick={() => setModal("resolution")}
            >
              Other resolution
            </button>
          </div>
        </div>
      )}

      {modal === "owner" && (
        <AssignOwnerModal
          assetIds={selectedAssetIds}
          findingCount={selected.size}
          reviewer={reviewer}
          onClose={closeModal}
          onDone={onBulkDone}
        />
      )}
      {modal === "resolution" && (
        <BulkResolutionModal
          findingIds={[...selected]}
          reviewer={reviewer}
          onClose={closeModal}
          onDone={onBulkDone}
        />
      )}
    </div>
  );
}
