"use client";

import Link from "next/link";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";

export default function CoveragePage() {
  const { data, loading, error } = useApi(() => api.getCoverage(), []);

  return (
    <div>
      <h2>Coverage &amp; orphan-asset report</h2>
      <p className="muted">
        How much of the asset graph has a confirmed owner.
      </p>

      {error && <div className="error-box">{error}</div>}
      {loading && <p className="muted">Loading…</p>}

      {data && (
        <>
          <div className="stat-row">
            <div className="stat">
              <div className="value">{data.total_assets}</div>
              <div className="label">Total assets</div>
            </div>
            <div className="stat">
              <div className="value">{data.active_assets}</div>
              <div className="label">Active assets</div>
            </div>
            <div className="stat">
              <div className="value">{(data.pct_owner_confidence_gte_0_8 * 100).toFixed(0)}%</div>
              <div className="label">Owner confidence ≥ 0.8</div>
            </div>
          </div>

          <div className="card">
            <h3 style={{ marginTop: 0 }}>Ownership resolution</h3>
            <table>
              <thead>
                <tr>
                  <th>Outcome</th>
                  <th>Count</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Resolved</td>
                  <td>{data.resolved_ownership}</td>
                </tr>
                <tr>
                  <td>Disputed</td>
                  <td>{data.disputed_ownership}</td>
                </tr>
                <tr>
                  <td>
                    Orphan — <Link href="/assets">view in explorer</Link>
                  </td>
                  <td>{data.orphan_ownership}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
