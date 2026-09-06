"use client";

import Link from "next/link";
import { useState } from "react";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { downloadCsv } from "@/lib/csv";

export default function AssetExplorerPage() {
  const [typeFilter, setTypeFilter] = useState("");
  const [activeOnly, setActiveOnly] = useState(false);
  const [valueFilter, setValueFilter] = useState("");
  const [appliedClauses, setAppliedClauses] = useState<string[]>([]);

  const { data, loading, error } = useApi(() => api.listAssets(appliedClauses), [appliedClauses]);

  function applyFilters() {
    const clauses: string[] = [];
    if (typeFilter) clauses.push(`type=${typeFilter}`);
    if (activeOnly) clauses.push("is_active=true");
    if (valueFilter) clauses.push(`value=${valueFilter}`);
    setAppliedClauses(clauses);
  }

  function exportCsv() {
    if (!data) return;
    downloadCsv(
      "assets.csv",
      data.map((a) => ({
        id: a.id,
        value: a.value,
        type: a.type,
        is_active: a.is_active,
        confidence_in_scope: a.confidence_in_scope,
        first_seen: a.first_seen,
        last_seen: a.last_seen,
      })),
    );
  }

  return (
    <div>
      <h2>Asset explorer</h2>
      <p className="muted">
        Filter/search over the asset graph — click an asset for its ownership and edges.
      </p>

      <div className="filters">
        <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
          <option value="">any type</option>
          <option value="domain">domain</option>
          <option value="subdomain">subdomain</option>
          <option value="ip">ip</option>
          <option value="url">url</option>
          <option value="http_service">http_service</option>
          <option value="tcp_service">tcp_service</option>
          <option value="cloud_resource">cloud_resource</option>
          <option value="llm_endpoint">llm_endpoint</option>
          <option value="mcp_server">mcp_server</option>
          <option value="vector_db">vector_db</option>
          <option value="model_registry">model_registry</option>
          <option value="notebook">notebook</option>
          <option value="ai_app">ai_app</option>
          <option value="ai_saas_tenant">ai_saas_tenant</option>
        </select>
        <input
          placeholder="exact value…"
          value={valueFilter}
          onChange={(e) => setValueFilter(e.target.value)}
        />
        <label>
          <input
            type="checkbox"
            checked={activeOnly}
            onChange={(e) => setActiveOnly(e.target.checked)}
          />{" "}
          active only
        </label>
        <button onClick={applyFilters}>Search</button>
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
                <th>Value</th>
                <th>Type</th>
                <th>Active</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {data.length === 0 && (
                <tr>
                  <td colSpan={4} className="muted">
                    No assets match.
                  </td>
                </tr>
              )}
              {data.map((asset) => (
                <tr key={asset.id}>
                  <td>
                    <Link href={`/assets/${asset.id}`}>{asset.value}</Link>
                  </td>
                  <td>{asset.type}</td>
                  <td>{asset.is_active ? "yes" : "no"}</td>
                  <td>{new Date(asset.last_seen).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
