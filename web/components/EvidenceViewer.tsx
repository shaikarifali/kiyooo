import type { EvidenceOut } from "@/lib/types";

/** Screenshots, headers, cert details — rendered as pretty-printed JSON
 * since evidence content is heterogeneous per `EvidenceKind`. Secrets are
 * already redacted server-side at ingest (Stage 11, invariant #7) before
 * this content is ever persisted — the `redacted` badge just surfaces
 * that it happened, it doesn't do any redaction itself.
 */
export function EvidenceViewer({ evidence }: { evidence: EvidenceOut[] }) {
  if (evidence.length === 0) {
    return <p className="muted">No evidence linked to this finding.</p>;
  }
  return (
    <div>
      {evidence.map((item) => (
        <div key={item.id} className="card" style={{ marginBottom: 12 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <strong>
              {item.kind} <span className="muted">({item.id})</span>
            </strong>
            <div style={{ display: "flex", gap: 6 }}>
              {item.redacted && <span className="badge medium">redacted</span>}
              {item.injection_suspected && <span className="badge critical">injection?</span>}
            </div>
          </div>
          <div className="muted" style={{ fontSize: 12, margin: "4px 0" }}>
            {item.source_tool} — {new Date(item.collected_at).toLocaleString()}
          </div>
          <pre className="evidence">{JSON.stringify(item.content_inline, null, 2)}</pre>
        </div>
      ))}
    </div>
  );
}
