"use client";

import Link from "next/link";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

function sum(counts: Record<string, number>, keys: string[]): number {
  return keys.reduce((total, key) => total + (counts[key] ?? 0), 0);
}

export default function DashboardPage() {
  const { data, loading, error } = useApi(() => api.getDashboard(), []);

  return (
    <div>
      <h2>Dashboard</h2>
      <p className="muted">
        Triage funnel, model/human agreement, and LLM spend. Low-agreement
        categories are the ones whose triage_hints need rewriting.
      </p>

      {error && <div className="error-box">{error}</div>}
      {loading && <p className="muted">Loading…</p>}

      {data && (
        <>
          <div className="card" style={{ borderColor: "var(--accent)" }}>
            <h3 style={{ marginTop: 0 }}>Human in the loop — nothing closes on its own</h3>
            <p className="muted" style={{ marginBottom: 0 }}>
              The model drafts a verdict for every candidate finding — including &quot;this looks
              like a false positive&quot; — but it never acts on that draft. A finding only leaves
              the queue (suppressed, routed, closed) after a person clicks Agree or Disagree on{" "}
              <Link href="/triage">the triage queue</Link>. The numbers below are that pipeline,
              made visible.
            </p>
          </div>

          {(() => {
            const notYetAdjudicated = data.status_counts["new"] ?? 0;
            const awaitingHuman = sum(data.status_counts, ["triaging", "triaged"]);
            const humanConfirmed = sum(data.status_counts, [
              "routed",
              "accepted_risk",
              "verification_pending",
              "fixed",
              "regressed",
            ]);
            const suppressed = data.status_counts["suppressed"] ?? 0;
            const total = notYetAdjudicated + awaitingHuman + humanConfirmed + suppressed;
            const criticalHighDelivered = sum(data.routed_severity_counts, [
              "critical",
              "high",
            ]);

            return (
              <>
                <div className="stat-row">
                  <div className="stat">
                    <div className="value">{total}</div>
                    <div className="label">Total findings tracked</div>
                  </div>
                  <div className="stat">
                    <div className="value">{awaitingHuman}</div>
                    <div className="label">Awaiting a human decision</div>
                  </div>
                  <div className="stat">
                    <div className="value">{humanConfirmed}</div>
                    <div className="label">Human-confirmed &amp; routed</div>
                  </div>
                  <div className="stat">
                    <div className="value">{criticalHighDelivered}</div>
                    <div className="label">Confirmed critical/high delivered</div>
                  </div>
                </div>

                <div className="grid-two">
                  <div className="card">
                    <h3 style={{ marginTop: 0 }}>What the model drafted (unconfirmed)</h3>
                    <p className="muted" style={{ fontSize: 13, marginTop: -4 }}>
                      The model&apos;s own latest verdict per finding — its proposal for what&apos;s
                      noise and what&apos;s real, before any human weighs in.
                    </p>
                    {Object.keys(data.verdict_counts).length === 0 ? (
                      <p className="muted">No verdicts recorded yet.</p>
                    ) : (
                      <table>
                        <tbody>
                          {Object.entries(data.verdict_counts).map(([verdict, count]) => (
                            <tr key={verdict}>
                              <td>{verdict.replace(/_/g, " ")}</td>
                              <td style={{ textAlign: "right" }}>
                                <strong>{count}</strong>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>

                  <div className="card">
                    <h3 style={{ marginTop: 0 }}>Confirmed true positives, by severity</h3>
                    <p className="muted" style={{ fontSize: 13, marginTop: -4 }}>
                      Only <code>routed</code> findings — a human already agreed these are real and
                      approved sending them to the accountable owner.
                    </p>
                    {Object.keys(data.routed_severity_counts).length === 0 ? (
                      <p className="muted">Nothing routed yet.</p>
                    ) : (
                      <table>
                        <tbody>
                          {SEVERITY_ORDER.filter((s) => data.routed_severity_counts[s]).map(
                            (severity) => (
                              <tr key={severity}>
                                <td>
                                  <span className={`badge ${severity}`}>{severity}</span>
                                </td>
                                <td style={{ textAlign: "right" }}>
                                  <strong>{data.routed_severity_counts[severity]}</strong>
                                </td>
                              </tr>
                            ),
                          )}
                        </tbody>
                      </table>
                    )}
                  </div>
                </div>
              </>
            );
          })()}

          <div className="stat-row">
            <div className="stat">
              <div className="value">${data.total_cost_usd.toFixed(2)}</div>
              <div className="label">Total LLM spend</div>
            </div>
            <div className="stat">
              <div className="value">{data.scan_run_count}</div>
              <div className="label">Scan runs</div>
            </div>
            <div className="stat">
              <div className="value">${data.cost_per_scan_run_usd.toFixed(4)}</div>
              <div className="label">Cost per scan run</div>
            </div>
          </div>

          <div className="card">
            <h3 style={{ marginTop: 0 }}>Agreement by category</h3>
            <table>
              <thead>
                <tr>
                  <th>Category</th>
                  <th>Model</th>
                  <th>Prompt version</th>
                  <th>Agreement</th>
                  <th>n</th>
                </tr>
              </thead>
              <tbody>
                {data.agreement.length === 0 && (
                  <tr>
                    <td colSpan={5} className="muted">
                      No human reviews recorded yet.
                    </td>
                  </tr>
                )}
                {data.agreement.map((row, i) => (
                  <tr key={i}>
                    <td>{row.category_id}</td>
                    <td>{row.model}</td>
                    <td>{row.prompt_version}</td>
                    <td>
                      <span className={`badge ${row.rate < 0.7 ? "critical" : "low"}`}>
                        {(row.rate * 100).toFixed(0)}%
                      </span>
                    </td>
                    <td>{row.total}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
