"use client";

import Link from "next/link";
import { useState } from "react";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString();
}

const KIND_LABEL: Record<string, string> = {
  ASSET_NEW: "New asset",
  ASSET_GONE: "Asset gone",
  PORT_OPENED: "Port opened",
  PORT_CLOSED: "Port closed",
  TECH_CHANGED: "Tech changed",
  DECOMMISSION_CANDIDATE: "Decommission candidate",
  CERT_CHANGED: "Cert changed",
  DNS_CHANGED: "DNS changed",
  TAKEOVER_RISK: "Takeover risk",
  AUTH_REMOVED: "Auth removed",
  WENT_PUBLIC: "Went public",
  CONTENT_CHANGED: "Content changed",
};

export default function ChangeFeedPage() {
  const [hours, setHours] = useState(24);
  const { data, loading, error, refetch } = useApi(() => api.listChanges(hours), [hours]);

  return (
    <div>
      <h2>What&apos;s new</h2>
      <p className="muted">
        Change events across the asset graph — the default landing page.
      </p>

      <div className="filters">
        <label>
          Lookback:
          <select
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
            style={{ marginLeft: 8 }}
          >
            <option value={24}>24 hours</option>
            <option value={24 * 7}>7 days</option>
            <option value={24 * 30}>30 days</option>
          </select>
        </label>
        <button className="secondary" onClick={refetch}>
          Refresh
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}
      {loading && <p className="muted">Loading…</p>}

      {data && (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Kind</th>
                <th>Asset</th>
                <th>Severity hint</th>
              </tr>
            </thead>
            <tbody>
              {data.length === 0 && (
                <tr>
                  <td colSpan={4} className="muted">
                    No changes in this window.
                  </td>
                </tr>
              )}
              {data.map((event) => (
                <tr key={event.id}>
                  <td>{formatTime(event.occurred_at)}</td>
                  <td>{KIND_LABEL[event.kind] ?? event.kind}</td>
                  <td>
                    <Link href={`/assets/${event.asset_id}`}>
                      {event.asset_id.slice(0, 8)}…
                    </Link>
                  </td>
                  <td>{event.severity_hint ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
