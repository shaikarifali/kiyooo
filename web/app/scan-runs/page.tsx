"use client";

import Link from "next/link";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { ScanRunOut } from "@/lib/types";

function durationLabel(run: ScanRunOut): string {
  if (!run.finished_at) return "—";
  const ms = new Date(run.finished_at).getTime() - new Date(run.started_at).getTime();
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return `${m}m ${rem}s`;
}

export default function ScanRunsPage() {
  const { data, loading, error } = useApi(() => api.listScanRuns(50), []);

  return (
    <div>
      <h2>Scan run history</h2>
      <p className="muted">
        Every completed scan run, most recent first — the correlation ID every finding, change
        event, and log line traces back to. Filter <Link href="/triage">Triage queue</Link> or{" "}
        <Link href="/">the change feed</Link> to a single run via its ID.
      </p>

      {error && <div className="error-box">{error}</div>}
      {loading && <p className="muted">Loading…</p>}

      {data && (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Started</th>
                <th>Finished</th>
                <th>Duration</th>
                <th>Status</th>
                <th>Trigger</th>
                <th>Run ID</th>
              </tr>
            </thead>
            <tbody>
              {data.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    No completed scan runs yet.
                  </td>
                </tr>
              )}
              {data.map((run) => (
                <tr key={run.id}>
                  <td>{new Date(run.started_at).toLocaleString()}</td>
                  <td>{run.finished_at ? new Date(run.finished_at).toLocaleString() : "—"}</td>
                  <td>{durationLabel(run)}</td>
                  <td>
                    <span className={`badge ${run.status === "completed" ? "low" : "critical"}`}>
                      {run.status}
                    </span>
                  </td>
                  <td>{run.trigger}</td>
                  <td>
                    <code style={{ fontSize: 12 }}>{run.id}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
