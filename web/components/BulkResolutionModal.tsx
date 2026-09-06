"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import type { VerdictValue } from "@/lib/types";

const RESOLUTIONS: { value: VerdictValue; label: string; hint: string }[] = [
  { value: "true_positive", label: "Confirm (true positive)", hint: "agree with the model" },
  { value: "false_positive", label: "Reject (false positive)", hint: "disagree with the model" },
  {
    value: "not_exploitable",
    label: "Not exploitable",
    hint: "real, but not reachable/dangerous here",
  },
  { value: "needs_human", label: "Needs human", hint: "send back for individual review" },
];

/** Bulk resolution — reuses the same `POST /api/findings/{id}/review`
 * endpoint the single-finding triage page's Agree/Disagree buttons call,
 * once per selected finding, with one shared verdict + rationale. This is
 * a human decision applied to many findings at once, not a new kind of
 * decision (invariant #4/#6: the model still never resolves anything on
 * its own — a human is choosing the verdict for every row here).
 */
export function BulkResolutionModal({
  findingIds,
  reviewer,
  onClose,
  onDone,
}: {
  findingIds: string[];
  reviewer: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const [verdict, setVerdict] = useState<VerdictValue>("true_positive");
  const [rationale, setRationale] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<{ ok: number; failed: number } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function resolve() {
    if (!reviewer.trim() || !rationale.trim()) {
      setErr("Reviewer and rationale are both required.");
      return;
    }
    setSubmitting(true);
    setErr(null);
    let ok = 0;
    let failed = 0;
    for (const id of findingIds) {
      try {
        await api.submitReview(id, { verdict, rationale, reviewer });
        ok++;
      } catch {
        failed++;
      }
    }
    setSubmitting(false);
    setResult({ ok, failed });
    if (failed === 0) onDone();
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h3>Other resolution</h3>
          <button className="modal-close" onClick={onClose}>
            ×
          </button>
        </div>

        <div className="modal-summary">
          <span className="n">{findingIds.length}</span> selected finding
          {findingIds.length === 1 ? "" : "s"}
        </div>

        <div className="picker-list" style={{ marginBottom: 10 }}>
          {RESOLUTIONS.map((r) => (
            <div
              key={r.value}
              className={`picker-row ${verdict === r.value ? "selected" : ""}`}
              onClick={() => setVerdict(r.value)}
            >
              <span>{r.label}</span>
              <span className="kind">{r.hint}</span>
            </div>
          ))}
        </div>

        <input
          placeholder="you@example.com"
          value={reviewer}
          readOnly
          style={{ width: "100%", marginBottom: 8, opacity: 0.7 }}
        />
        <textarea
          placeholder="Rationale (applied to every selected finding)"
          value={rationale}
          onChange={(e) => setRationale(e.target.value)}
          rows={3}
          style={{ width: "100%", marginBottom: 10 }}
        />

        {err && <div className="error-box">{err}</div>}
        {result && (
          <p className={result.failed ? "error-box" : "muted"} style={{ marginTop: 4 }}>
            {result.ok} resolved{result.failed ? `, ${result.failed} failed — try those again.` : "."}
          </p>
        )}

        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <button className="secondary" onClick={onClose}>
            {result && !result.failed ? "Close" : "Cancel"}
          </button>
          <button disabled={submitting} onClick={resolve}>
            {submitting ? "Resolving…" : "Apply to all"}
          </button>
        </div>
      </div>
    </div>
  );
}
