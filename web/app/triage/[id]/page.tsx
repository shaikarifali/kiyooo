"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { SeverityBadge } from "@/components/SeverityBadge";
import { EvidenceViewer } from "@/components/EvidenceViewer";
import { ClaimVerification } from "@/components/ClaimVerification";
import type { VerdictValue } from "@/lib/types";

export default function FindingDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const { data, loading, error, refetch } = useApi(() => api.getFinding(params.id), [params.id]);

  const [reviewer, setReviewer] = useState("");
  const [rationale, setRationale] = useState("");
  const [submitting, setSubmitting] = useState<VerdictValue | null>(null);
  const [reviewError, setReviewError] = useState<string | null>(null);
  const [reviewResult, setReviewResult] = useState<string | null>(null);

  async function submitReview(verdict: VerdictValue) {
    if (!reviewer.trim() || !rationale.trim()) {
      setReviewError("Reviewer and rationale are both required.");
      return;
    }
    setSubmitting(verdict);
    setReviewError(null);
    try {
      const result = await api.submitReview(params.id, { verdict, rationale, reviewer });
      setReviewResult(
        result.agreed_with_model
          ? "Recorded — you agreed with the model."
          : "Recorded — you disagreed with the model.",
      );
      refetch();
    } catch (err) {
      setReviewError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(null);
    }
  }

  if (loading) return <p className="muted">Loading…</p>;
  if (error) return <div className="error-box">{error}</div>;
  if (!data) return null;

  const {
    finding,
    asset,
    latest_verdict: verdict,
    evidence,
    identifier_verifications,
    human_reviews,
  } = data;

  const humanDecided = finding.status !== "new" && finding.status !== "triaging" && finding.status !== "triaged";

  return (
    <div>
      <button className="secondary" onClick={() => router.push("/triage")}>
        ← back to queue
      </button>

      <h2 style={{ marginTop: 16 }}>
        <SeverityBadge severity={finding.raw_severity} /> {finding.title}
      </h2>
      <p className="muted">
        {finding.category_id} on <Link href={`/assets/${asset.id}`}>{asset.value}</Link> (
        {asset.type})
      </p>

      <div className="grid-two">
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h3 style={{ marginTop: 0, marginBottom: 0 }}>Model verdict</h3>
            {verdict && (
              <span className={`badge ${humanDecided ? "low" : "medium"}`}>
                {humanDecided ? "human-confirmed" : "draft — awaiting human decision"}
              </span>
            )}
          </div>
          {verdict ? (
            <>
              <p className="muted" style={{ fontSize: 13 }}>
                The model proposed this — it has no authority to close, suppress, or route
                anything on its own. It only becomes real once a human agrees below.
              </p>
              <p>
                <strong>{verdict.verdict}</strong> — confidence {(verdict.confidence * 100).toFixed(0)}%,
                adjusted severity <SeverityBadge severity={verdict.adjusted_severity} />
              </p>
              <p>{verdict.reasoning}</p>
              <p className="muted">
                <strong>Why it matters:</strong> {verdict.business_impact_hypothesis}
              </p>
              {verdict.remediation && (
                <>
                  <strong>Remediation</strong>
                  <pre className="evidence">{JSON.stringify(verdict.remediation, null, 2)}</pre>
                </>
              )}
              <p className="muted" style={{ fontSize: 12 }}>
                {verdict.model} · {verdict.prompt_version} · ${verdict.cost_usd.toFixed(4)}
              </p>
            </>
          ) : (
            <p className="muted">No verdict yet.</p>
          )}
        </div>

        <div className="card">
          <h3 style={{ marginTop: 0 }}>Your review</h3>
          {human_reviews.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <p className="muted" style={{ fontSize: 12, textTransform: "uppercase", marginBottom: 4 }}>
                Decision history
              </p>
              {human_reviews.map((r) => (
                <div
                  key={r.id}
                  style={{
                    borderLeft: "2px solid var(--border)",
                    paddingLeft: 10,
                    marginBottom: 8,
                  }}
                >
                  <p style={{ margin: 0 }}>
                    <span className={`badge ${r.agreed_with_model ? "low" : "medium"}`}>
                      {r.agreed_with_model ? "agreed" : "disagreed"}
                    </span>{" "}
                    → <strong>{r.final_verdict.replace(/_/g, " ")}</strong>
                  </p>
                  <p className="muted" style={{ margin: "4px 0", fontSize: 13 }}>
                    {r.rationale}
                  </p>
                  <p className="muted" style={{ margin: 0, fontSize: 11 }}>
                    {r.reviewer} · {new Date(r.created_at).toLocaleString()}
                  </p>
                </div>
              ))}
            </div>
          )}
          <div style={{ marginBottom: 8 }}>
            <input
              placeholder="you@example.com"
              value={reviewer}
              onChange={(e) => setReviewer(e.target.value)}
              style={{ width: "100%", marginBottom: 8 }}
            />
            <textarea
              placeholder="Rationale"
              value={rationale}
              onChange={(e) => setRationale(e.target.value)}
              rows={3}
              style={{ width: "100%" }}
            />
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              disabled={submitting !== null}
              onClick={() => submitReview("true_positive")}
            >
              Agree (true positive)
            </button>
            <button
              className="secondary"
              disabled={submitting !== null}
              onClick={() => submitReview("false_positive")}
            >
              Disagree (false positive)
            </button>
          </div>
          {reviewError && (
            <div className="error-box" style={{ marginTop: 8 }}>
              {reviewError}
            </div>
          )}
          {reviewResult && <p style={{ color: "var(--ok)", marginTop: 8 }}>{reviewResult}</p>}
        </div>
      </div>

      <h3>Claim verification</h3>
      <p className="muted" style={{ marginTop: -8 }}>
        Every identifier the model cited (CVE/CWE/version/hostname), checked against NVD/KEV/OSV/
        DNS or the evidence bundle itself — never taken on faith.
      </p>
      <ClaimVerification identifierVerifications={identifier_verifications} />

      <h3>Evidence</h3>
      <EvidenceViewer evidence={evidence} />
    </div>
  );
}
