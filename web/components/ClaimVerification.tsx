import type { IdentifierVerificationOut, IdentifierStatus } from "@/lib/types";

// invariant #4, made visible: "every model claim must cite an evidence ID
// present in the bundle; the validator rejects uncited claims." This is
// the audit trail proving that happened for THIS finding — every CVE/CWE/
// version/hostname the model cited, and what checking it against NVD/KEV/
// OSV/DNS/the evidence bundle itself actually found. `hallucinated` is the
// status that matters most: a claim nothing could verify.
const STATUS_BADGE: Record<IdentifierStatus, string> = {
  verified: "low",
  not_found: "info",
  mismatch: "medium",
  hallucinated: "critical",
};

const STATUS_LABEL: Record<IdentifierStatus, string> = {
  verified: "verified",
  not_found: "not found",
  mismatch: "mismatch",
  hallucinated: "hallucinated",
};

export function ClaimVerification({
  identifierVerifications,
}: {
  identifierVerifications: IdentifierVerificationOut[];
}) {
  if (identifierVerifications.length === 0) {
    return (
      <p className="muted">
        The model didn&apos;t cite any checkable identifiers (CVE/CWE/version/hostname) for this
        finding.
      </p>
    );
  }

  return (
    <div className="card">
      <table>
        <thead>
          <tr>
            <th>Kind</th>
            <th>Claimed</th>
            <th>Source</th>
            <th>Checked against</th>
            <th>Result</th>
          </tr>
        </thead>
        <tbody>
          {identifierVerifications.map((iv, i) => (
            <tr key={i}>
              <td>{iv.kind.toUpperCase()}</td>
              <td>
                <code>{iv.claimed_value}</code>
              </td>
              <td className="muted">{iv.source}</td>
              <td className="muted">
                {iv.authority ? iv.authority.toUpperCase() : "—"}
                {iv.resolved_value && iv.resolved_value !== iv.claimed_value && (
                  <>
                    {" "}
                    → <code>{iv.resolved_value}</code>
                  </>
                )}
              </td>
              <td>
                <span className={`badge ${STATUS_BADGE[iv.status]}`}>
                  {STATUS_LABEL[iv.status]}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
