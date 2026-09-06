"use client";

import { useEffect, useMemo, useState } from "react";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type {
  ExclusionSource,
  OrgRelationship,
  ScopeAction,
  SeedKind,
} from "@/lib/types";

const SEED_KIND_OPTIONS: { value: SeedKind; label: string }[] = [
  { value: "apex_domain", label: "Domain" },
  { value: "wildcard", label: "Wildcard" },
  { value: "subdomain", label: "Subdomain" },
  { value: "url", label: "URL" },
  { value: "ip", label: "IP" },
  { value: "cidr", label: "CIDR" },
  { value: "asn", label: "ASN" },
  { value: "cloud_account", label: "Cloud account" },
  { value: "github_org", label: "GitHub org" },
  { value: "saas_tenant", label: "SaaS tenant" },
  { value: "brand_term", label: "Brand term" },
  { value: "email_domain", label: "Email domain" },
];

// ScopeGuard can only enforce these against a network target — the other
// seed kinds (github_org/saas_tenant/brand_term) are storable but not yet
// checkable, so exclusion doesn't offer them (matches cli.py's
// _EXCLUSION_KIND_FLAGS exactly).
const EXCLUSION_KIND_OPTIONS: { value: SeedKind; label: string }[] = [
  { value: "apex_domain", label: "Domain" },
  { value: "wildcard", label: "Wildcard" },
  { value: "cidr", label: "CIDR" },
  { value: "ip", label: "IP" },
  { value: "url", label: "URL" },
];

const UNENFORCED_KINDS = new Set<SeedKind>(["github_org", "saas_tenant", "brand_term"]);

const RELATIONSHIP_OPTIONS: OrgRelationship[] = [
  "self",
  "subsidiary",
  "acquisition",
  "brand",
  "third_party",
  "prospect",
];

const EXCLUSION_SOURCE_OPTIONS: ExclusionSource[] = [
  "user",
  "shipped_default",
  "auto_cdn",
  "auto_shared_host",
];

export default function ScopePage() {
  const { data: orgs, loading: orgsLoading, error: orgsError, refetch: refetchOrgs } = useApi(
    () => api.listOrganizations(),
    [],
  );

  const [you, setYou] = useState("");
  const [selectedOrgId, setSelectedOrgId] = useState<string>("");
  const [showNewOrg, setShowNewOrg] = useState(false);

  useEffect(() => {
    if (!selectedOrgId && orgs && orgs.length > 0) {
      setSelectedOrgId(orgs[0].id);
    }
  }, [orgs, selectedOrgId]);

  const selectedOrg = useMemo(
    () => orgs?.find((o) => o.id === selectedOrgId) ?? null,
    [orgs, selectedOrgId],
  );

  const {
    data: seeds,
    loading: seedsLoading,
    error: seedsError,
    refetch: refetchSeeds,
  } = useApi(() => (selectedOrgId ? api.listSeeds(selectedOrgId) : Promise.resolve([])), [
    selectedOrgId,
  ]);

  const {
    data: exclusions,
    loading: exclusionsLoading,
    error: exclusionsError,
    refetch: refetchExclusions,
  } = useApi(
    () => (selectedOrgId ? api.listExclusions(selectedOrgId) : api.listExclusions()),
    [selectedOrgId],
  );

  return (
    <div>
      <h2>Scope</h2>
      <p className="muted">
        What kiyooo should scan — organizations, their seeds (domains, wildcards, IPs,
        CIDRs, ...), and exclusions. Mirrors <code>kiyooo org/seed/exclusion</code> 1:1;
        anything done here is also a CLI command, and vice versa. See{" "}
        <code>scope.yaml</code> for the file-based alternative — this is additive, not a
        replacement.
      </p>

      <div className="filters">
        <label>
          Your email:
          <input
            placeholder="you@example.com"
            value={you}
            onChange={(e) => setYou(e.target.value)}
            style={{ marginLeft: 8, width: 220 }}
          />
        </label>
      </div>

      {orgsError && <div className="error-box">{orgsError}</div>}
      {orgsLoading && <p className="muted">Loading organizations…</p>}

      {orgs && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Organization</h3>
          {orgs.length === 0 && !showNewOrg && (
            <p className="muted">No organizations yet — create one to add seeds.</p>
          )}
          {orgs.length > 0 && (
            <div className="filters" style={{ marginBottom: showNewOrg ? 16 : 0 }}>
              <select value={selectedOrgId} onChange={(e) => setSelectedOrgId(e.target.value)}>
                {orgs.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.slug} — {o.name} ({o.relationship})
                  </option>
                ))}
              </select>
              <button className="secondary" onClick={() => setShowNewOrg((s) => !s)}>
                {showNewOrg ? "Cancel" : "+ New organization"}
              </button>
            </div>
          )}
          {(showNewOrg || orgs.length === 0) && (
            <NewOrgForm
              you={you}
              orgs={orgs}
              onCreated={(id) => {
                setSelectedOrgId(id);
                setShowNewOrg(false);
                refetchOrgs();
              }}
            />
          )}
          {selectedOrg && (
            <p className="muted" style={{ marginTop: 12 }}>
              <b>Active scanning</b>{" "}
              {selectedOrg.active_scanning_allowed ? (
                <span className="badge low">allowed</span>
              ) : (
                <span className="badge info">passive-only</span>
              )}
              {selectedOrg.relationship === "third_party" && (
                <span className="muted"> — third_party orgs are always passive-only</span>
              )}
              {selectedOrg.parent_org_id && (
                <>
                  {" "}
                  <b>Parent</b>{" "}
                  {orgs?.find((o) => o.id === selectedOrg.parent_org_id)?.slug ?? "…"}
                </>
              )}
            </p>
          )}
        </div>
      )}

      {selectedOrg && (
        <>
          <h3 style={{ marginTop: 24 }}>
            Seeds — {selectedOrg.slug}
          </h3>
          <div className="card">
            <AddSeedForm orgId={selectedOrg.id} you={you} onAdded={refetchSeeds} />
          </div>
          {seedsError && <div className="error-box">{seedsError}</div>}
          {seedsLoading && <p className="muted">Loading seeds…</p>}
          {seeds && (
            <div className="card">
              <table>
                <thead>
                  <tr>
                    <th>Kind</th>
                    <th>Value</th>
                    <th>Action</th>
                    <th>Verified</th>
                    <th>Active scan</th>
                    <th>Added by</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {seeds.length === 0 && (
                    <tr>
                      <td colSpan={7} className="muted">
                        No seeds yet — add one above.
                      </td>
                    </tr>
                  )}
                  {seeds.map((s) => (
                    <tr key={s.id}>
                      <td>
                        {s.kind}
                        {UNENFORCED_KINDS.has(s.kind) && (
                          <span className="muted" title="Not yet checkable by ScopeGuard">
                            {" "}
                            *
                          </span>
                        )}
                      </td>
                      <td>
                        <code>{s.value}</code>
                      </td>
                      <td>
                        <span className={`badge ${s.scope_action === "exclude" ? "critical" : "low"}`}>
                          {s.scope_action}
                        </span>
                      </td>
                      <td>{s.verified ? "yes" : "no"}</td>
                      <td>
                        {s.active_scan_allowed === null
                          ? "org default"
                          : s.active_scan_allowed
                            ? "yes"
                            : "no"}
                      </td>
                      <td>{s.added_by}</td>
                      <td>
                        <button
                          className="secondary"
                          onClick={() => api.disableSeed(s.id).then(refetchSeeds)}
                        >
                          Disable
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="muted" style={{ fontSize: 12, marginTop: 8 }}>
                * github_org/saas_tenant/brand_term seeds are stored but not yet checkable by
                ScopeGuard — no code path resolves them to a network target yet.
              </p>
            </div>
          )}

          <h3 style={{ marginTop: 24 }}>
            Exclusions — {selectedOrg.slug} + global
          </h3>
          <div className="card">
            <AddExclusionForm orgId={selectedOrg.id} onAdded={refetchExclusions} />
          </div>
          {exclusionsError && <div className="error-box">{exclusionsError}</div>}
          {exclusionsLoading && <p className="muted">Loading exclusions…</p>}
          {exclusions && (
            <div className="card">
              <table>
                <thead>
                  <tr>
                    <th>Kind</th>
                    <th>Value</th>
                    <th>Reason</th>
                    <th>Source</th>
                    <th>Scope</th>
                  </tr>
                </thead>
                <tbody>
                  {exclusions.length === 0 && (
                    <tr>
                      <td colSpan={5} className="muted">
                        No exclusions.
                      </td>
                    </tr>
                  )}
                  {exclusions.map((e) => (
                    <tr key={e.id}>
                      <td>{e.kind}</td>
                      <td>
                        <code>{e.value}</code>
                      </td>
                      <td>{e.reason}</td>
                      <td className="muted">{e.source}</td>
                      <td>
                        <span className={`badge ${e.org_id === null ? "medium" : "info"}`}>
                          {e.org_id === null ? "global" : "org"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function NewOrgForm({
  you,
  orgs,
  onCreated,
}: {
  you: string;
  orgs: { id: string; slug: string; name: string }[] | null;
  onCreated: (id: string) => void;
}) {
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [relationship, setRelationship] = useState<OrgRelationship>("self");
  const [parentId, setParentId] = useState("");
  const [activeScanningAllowed, setActiveScanningAllowed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit() {
    if (!slug.trim() || !name.trim() || !you.trim()) {
      setErr("Slug, name, and your email (above) are all required.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const org = await api.createOrganization({
        slug: slug.trim(),
        name: name.trim(),
        relationship,
        parent_org_id: parentId || null,
        active_scanning_allowed: relationship === "third_party" ? false : activeScanningAllowed,
        created_by: you,
      });
      onCreated(org.id);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="filters">
        <input placeholder="slug, e.g. acme" value={slug} onChange={(e) => setSlug(e.target.value)} />
        <input
          placeholder="Display name, e.g. Acme Corporation"
          value={name}
          onChange={(e) => setName(e.target.value)}
          style={{ width: 260 }}
        />
        <select
          value={relationship}
          onChange={(e) => setRelationship(e.target.value as OrgRelationship)}
        >
          {RELATIONSHIP_OPTIONS.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        {orgs && orgs.length > 0 && (
          <select value={parentId} onChange={(e) => setParentId(e.target.value)}>
            <option value="">no parent</option>
            {orgs.map((o) => (
              <option key={o.id} value={o.id}>
                parent: {o.slug}
              </option>
            ))}
          </select>
        )}
        <label>
          <input
            type="checkbox"
            checked={activeScanningAllowed}
            disabled={relationship === "third_party"}
            onChange={(e) => setActiveScanningAllowed(e.target.checked)}
          />{" "}
          active scanning allowed
        </label>
        <button disabled={busy} onClick={submit}>
          {busy ? "Creating…" : "Create"}
        </button>
      </div>
      {relationship === "third_party" && (
        <p className="muted" style={{ fontSize: 12 }}>
          third_party orgs are always passive-only — active scanning stays off regardless of the
          checkbox above.
        </p>
      )}
      {err && <div className="error-box">{err}</div>}
    </div>
  );
}

function AddSeedForm({
  orgId,
  you,
  onAdded,
}: {
  orgId: string;
  you: string;
  onAdded: () => void;
}) {
  const [kind, setKind] = useState<SeedKind>("apex_domain");
  const [value, setValue] = useState("");
  const [exclude, setExclude] = useState(false);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit() {
    if (!value.trim() || !you.trim()) {
      setErr("Value and your email (above) are both required.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await api.createSeed({
        org_id: orgId,
        kind,
        value: value.trim(),
        scope_action: exclude ? "exclude" : "include",
        note: note.trim() || null,
        added_by: you,
      });
      setValue("");
      setNote("");
      onAdded();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="filters">
        <select value={kind} onChange={(e) => setKind(e.target.value as SeedKind)}>
          {SEED_KIND_OPTIONS.map((k) => (
            <option key={k.value} value={k.value}>
              {k.label}
            </option>
          ))}
        </select>
        <input
          placeholder="value, e.g. acme.example or *.acme.example"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          style={{ width: 260 }}
        />
        <input
          placeholder="note (optional)"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          style={{ width: 200 }}
        />
        <label>
          <input type="checkbox" checked={exclude} onChange={(e) => setExclude(e.target.checked)} />{" "}
          exclude
        </label>
        <button disabled={busy} onClick={submit}>
          {busy ? "Adding…" : "Add seed"}
        </button>
      </div>
      {err && <div className="error-box">{err}</div>}
    </div>
  );
}

function AddExclusionForm({ orgId, onAdded }: { orgId: string; onAdded: () => void }) {
  const [kind, setKind] = useState<SeedKind>("apex_domain");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const [source, setSource] = useState<ExclusionSource>("user");
  const [global, setGlobal] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit() {
    if (!value.trim() || !reason.trim()) {
      setErr("Value and reason are both required.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await api.createExclusion({
        org_id: global ? null : orgId,
        kind,
        value: value.trim(),
        reason: reason.trim(),
        source,
      });
      setValue("");
      setReason("");
      onAdded();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="filters">
        <select value={kind} onChange={(e) => setKind(e.target.value as SeedKind)}>
          {EXCLUSION_KIND_OPTIONS.map((k) => (
            <option key={k.value} value={k.value}>
              {k.label}
            </option>
          ))}
        </select>
        <input
          placeholder="value"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          style={{ width: 200 }}
        />
        <input
          placeholder="reason"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          style={{ width: 200 }}
        />
        <select value={source} onChange={(e) => setSource(e.target.value as ExclusionSource)}>
          {EXCLUSION_SOURCE_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <label>
          <input type="checkbox" checked={global} onChange={(e) => setGlobal(e.target.checked)} />{" "}
          global (applies to every org)
        </label>
        <button disabled={busy} onClick={submit}>
          {busy ? "Adding…" : "Add exclusion"}
        </button>
      </div>
      {err && <div className="error-box">{err}</div>}
    </div>
  );
}
