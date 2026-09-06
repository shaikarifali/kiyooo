"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { PreviewResult } from "@/lib/types";

const EXAMPLE = JSON.stringify(
  {
    asset: { type: "tcp_service", value: "10.0.0.5:3306" },
    evidence: [{ kind: "port_banner", content: { port: 3306 } }],
  },
  null,
  2,
);

export default function CategoryEditorPage() {
  const { data: categories, loading, error } = useApi(() => api.listCategories(), []);
  const [categoryId, setCategoryId] = useState("");
  const [payload, setPayload] = useState(EXAMPLE);
  const [result, setResult] = useState<PreviewResult | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (categories && categories.length > 0 && !categoryId) {
      setCategoryId(categories[0].id);
    }
  }, [categories, categoryId]);

  async function runPreview() {
    setBusy(true);
    setPreviewError(null);
    setResult(null);
    try {
      const body = JSON.parse(payload);
      const res = await api.previewCategory(categoryId, body);
      setResult(res);
    } catch (err) {
      setPreviewError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h2>Category editor</h2>
      <p className="muted">
        Live &quot;what would this match&quot; preview — runs the exact same predicate evaluator
        `kiyooo categories test` and live detection use. Paste a synthetic
        asset + evidence to see whether a category would fire.
      </p>

      {error && <div className="error-box">{error}</div>}
      {loading && <p className="muted">Loading categories…</p>}

      {categories && (
        <div className="grid-two">
          <div className="card">
            <label>
              Category
              <select
                value={categoryId}
                onChange={(e) => setCategoryId(e.target.value)}
                style={{ display: "block", width: "100%", marginTop: 4, marginBottom: 12 }}
              >
                {categories.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.id} ({c.severity_base}
                    {c.enabled ? "" : ", disabled"})
                  </option>
                ))}
              </select>
            </label>
            <label>
              Synthetic asset + evidence (JSON)
              <textarea
                value={payload}
                onChange={(e) => setPayload(e.target.value)}
                rows={14}
                style={{ display: "block", width: "100%", marginTop: 4, fontFamily: "monospace" }}
              />
            </label>
            <button onClick={runPreview} disabled={busy || !categoryId} style={{ marginTop: 8 }}>
              Run preview
            </button>
          </div>

          <div className="card">
            <h3 style={{ marginTop: 0 }}>Result</h3>
            {previewError && <div className="error-box">{previewError}</div>}
            {result && (
              <>
                <p>
                  <span className={`badge ${result.matched ? "low" : "info"}`}>
                    {result.matched ? "matches" : "no match"}
                  </span>
                </p>
                {result.discriminator && (
                  <p className="muted">Discriminator: {result.discriminator}</p>
                )}
                {result.evidence_ids.length > 0 && (
                  <p className="muted">Evidence: {result.evidence_ids.join(", ")}</p>
                )}
                {result.error && <div className="error-box">{result.error}</div>}
              </>
            )}
            {!result && !previewError && (
              <p className="muted">Run a preview to see the result here.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
