"use client";

import Link from "next/link";
import { api } from "@/lib/api";
import { SeverityBadge } from "@/components/SeverityBadge";
import { useApi } from "@/lib/useApi";
import { downloadCsv } from "@/lib/csv";
import type { AssetOut, FindingOut, Severity } from "@/lib/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const AI_ASSET_TYPES = [
  "llm_endpoint",
  "vector_db",
  "mcp_server",
  "model_registry",
  "ai_agent_webhook",
  "notebook",
  "ai_app",
  "ai_saas_tenant",
];

const AI_CATEGORY_IDS = [
  "exposed-inference-endpoint",
  "exposed-vector-store",
  "exposed-notebook",
  "leaked-ai-api-key",
  "exposed-mcp-server",
  "mcp-tool-poisoning-risk",
  "exposed-model-registry",
  "unsafe-model-artifact",
  "public-chatbot-excessive-agency",
  "shadow-ai-saas-tenant",
];

async function fetchAiAssets(): Promise<AssetOut[]> {
  const lists = await Promise.all(AI_ASSET_TYPES.map((t) => api.listAssets([`type=${t}`])));
  return lists.flat();
}

async function fetchAiFindings(): Promise<FindingOut[]> {
  const lists = await Promise.all(
    AI_CATEGORY_IDS.map((c) => api.listFindings({ category_id: c, limit: 200 })),
  );
  return lists.flat().sort((a, b) => (a.last_seen < b.last_seen ? 1 : -1));
}

export default function AiSurfacePage() {
  const {
    data: assets,
    loading: assetsLoading,
    error: assetsError,
  } = useApi(fetchAiAssets, []);
  const {
    data: findings,
    loading: findingsLoading,
    error: findingsError,
  } = useApi(fetchAiFindings, []);

  const severityCounts = SEVERITIES.map((sev) => ({
    sev,
    count: findings?.filter((f) => f.raw_severity === sev).length ?? 0,
  }));

  function exportFindingsCsv() {
    if (!findings) return;
    downloadCsv(
      "ai-attack-surface-findings.csv",
      findings.map((f) => ({
        id: f.id,
        severity: f.raw_severity,
        category_id: f.category_id,
        title: f.title,
        detector: f.detector,
        status: f.status,
        last_seen: f.last_seen,
        asset_id: f.asset_id,
      })),
    );
  }

  return (
    <div>
      <h2>AI attack surface</h2>
      <p className="muted">
        MCP servers, vector databases, model registries, notebook servers, and shadow AI SaaS
        tenants — kiyooo fingerprints these with its own passive recon, the same way it finds a
        subdomain or an open port. This isn&apos;t a wrapped vendor tool: there&apos;s no account
        to add or scan to configure here — anything discovered shows up below automatically, and
        every finding still goes through the same category match and LLM adjudication as
        everything else before reaching the <Link href="/triage">triage queue</Link>.
      </p>

      {findings && findings.length > 0 && (
        <div className="stat-row">
          {severityCounts.map(({ sev, count }) => (
            <div className="stat" key={sev}>
              <div className="value">{count}</div>
              <div className="label">{sev}</div>
            </div>
          ))}
        </div>
      )}

      <div className="card">
        <h3 style={{ marginTop: 0 }}>AI assets discovered</h3>
        {assetsError && <div className="error-box">{assetsError}</div>}
        {assetsLoading && <p className="muted">Loading…</p>}
        {assets && assets.length === 0 && (
          <p className="muted">
            None yet — <code>llm_endpoint</code>, <code>mcp_server</code>, <code>vector_db</code>,{" "}
            <code>model_registry</code>, <code>notebook</code>, <code>ai_app</code>,{" "}
            <code>ai_saas_tenant</code>, and <code>ai_agent_webhook</code> assets appear here once
            recon finds one.
          </p>
        )}
        {assets && assets.length > 0 && (
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
              {assets.map((asset) => (
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
        )}
      </div>

      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <h3 style={{ marginTop: 0 }}>AI findings</h3>
          {findings && findings.length > 0 && (
            <button className="secondary" onClick={exportFindingsCsv}>
              Export CSV
            </button>
          )}
        </div>
        {findingsError && <div className="error-box">{findingsError}</div>}
        {findingsLoading && <p className="muted">Loading…</p>}
        {findings && findings.length === 0 && (
          <p className="muted">
            No findings yet in any of the 10 AI &amp; agent surface categories.
          </p>
        )}
        {findings && findings.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Category</th>
                <th>Title</th>
                <th>Status</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.id}>
                  <td>
                    <SeverityBadge severity={f.raw_severity} />
                  </td>
                  <td>
                    <code>{f.category_id}</code>
                  </td>
                  <td>
                    <Link href={`/triage/${f.id}`}>{f.title}</Link>
                  </td>
                  <td>{f.status}</td>
                  <td>{new Date(f.last_seen).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
