"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { OwnerType } from "@/lib/types";

export default function AssetDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();

  const asset = useApi(() => api.getAsset(params.id), [params.id]);
  const ownership = useApi(() => api.getOwnership(params.id), [params.id]);
  const edges = useApi(() => api.getAssetEdges(params.id), [params.id]);

  const [ownerType, setOwnerType] = useState<OwnerType>("user");
  const [ownerRef, setOwnerRef] = useState("");
  const [reviewer, setReviewer] = useState("");
  const [overrideError, setOverrideError] = useState<string | null>(null);
  const [overrideBusy, setOverrideBusy] = useState(false);

  async function submitOverride() {
    if (!ownerRef.trim() || !reviewer.trim()) {
      setOverrideError("Owner and reviewer are both required.");
      return;
    }
    setOverrideBusy(true);
    setOverrideError(null);
    try {
      await api.overrideOwnership(params.id, { owner_type: ownerType, owner_ref: ownerRef, reviewer });
      ownership.refetch();
    } catch (err) {
      setOverrideError(err instanceof Error ? err.message : String(err));
    } finally {
      setOverrideBusy(false);
    }
  }

  if (asset.loading) return <p className="muted">Loading…</p>;
  if (asset.error) return <div className="error-box">{asset.error}</div>;
  if (!asset.data) return null;

  return (
    <div>
      <button className="secondary" onClick={() => router.push("/assets")}>
        ← back to explorer
      </button>

      <h2 style={{ marginTop: 16 }}>{asset.data.value}</h2>
      <p className="muted">
        {asset.data.type} · {asset.data.is_active ? "active" : "inactive"} · confidence in scope{" "}
        {(asset.data.confidence_in_scope * 100).toFixed(0)}%
      </p>

      <div className="grid-two">
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Ownership</h3>
          {ownership.loading && <p className="muted">Loading…</p>}
          {ownership.data ? (
            <p>
              <strong>{ownership.data.owner_ref}</strong> ({ownership.data.owner_type}) — source{" "}
              {ownership.data.source}, confidence {(ownership.data.confidence * 100).toFixed(0)}%
              {ownership.data.note && <span className="muted"> — {ownership.data.note}</span>}
            </p>
          ) : (
            !ownership.loading && (
              <p className="muted">Orphan — no confirmed owner. Confirm or reassign below.</p>
            )
          )}

          <h4>Confirm or reassign</h4>
          <select
            value={ownerType}
            onChange={(e) => setOwnerType(e.target.value as OwnerType)}
            style={{ marginBottom: 8 }}
          >
            <option value="user">user</option>
            <option value="team">team</option>
          </select>
          <input
            placeholder="owner (email or team id)"
            value={ownerRef}
            onChange={(e) => setOwnerRef(e.target.value)}
            style={{ display: "block", width: "100%", marginBottom: 8 }}
          />
          <input
            placeholder="your email"
            value={reviewer}
            onChange={(e) => setReviewer(e.target.value)}
            style={{ display: "block", width: "100%", marginBottom: 8 }}
          />
          <button disabled={overrideBusy} onClick={submitOverride}>
            Save override
          </button>
          {overrideError && (
            <div className="error-box" style={{ marginTop: 8 }}>
              {overrideError}
            </div>
          )}
        </div>

        <div className="card">
          <h3 style={{ marginTop: 0 }}>Related assets</h3>
          {edges.loading && <p className="muted">Loading…</p>}
          {edges.data && edges.data.length === 0 && (
            <p className="muted">No edges recorded for this asset.</p>
          )}
          {edges.data && edges.data.length > 0 && (
            <table>
              <thead>
                <tr>
                  <th>Relation</th>
                  <th>Other side</th>
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {edges.data.map((edge, i) => {
                  const isSrc = edge.src_asset_id === params.id;
                  const otherId = isSrc ? edge.dst_asset_id : edge.src_asset_id;
                  return (
                    <tr key={i}>
                      <td>
                        {isSrc ? edge.relation : `<- ${edge.relation}`}
                      </td>
                      <td>
                        <Link href={`/assets/${otherId}`}>{otherId.slice(0, 8)}…</Link>
                      </td>
                      <td>{(edge.confidence * 100).toFixed(0)}%</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
