"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { ModelPinOut, ModelPinRole, ProviderTestResultOut, RoleDefaultOut } from "@/lib/types";

const ROLE_LABELS: Record<ModelPinRole, string> = {
  bulk: "Bulk",
  escalation: "Escalation",
  embedding: "Embedding",
};

const ROLE_HELP: Record<ModelPinRole, string> = {
  bulk: "Runs first, on every finding. Local (Ollama) is the default — no per-finding cost.",
  escalation:
    "Runs only when the bulk pass is low-confidence, high/critical severity, or the category always escalates.",
  embedding:
    "Powers similar-past-decisions search (Stage 5's memory) — not part of adjudication itself.",
};

// Suggestions only, not a closed list — "ollama"/"anthropic" get this
// project's dedicated client; type ANY other name (openai, openrouter,
// vllm, a self-hosted server, literally anything) and it's bring-your-
// own-model, served as an OpenAI-compatible endpoint. A <datalist> keeps
// the field a plain <input>, never restricting what you can type.
const KNOWN_PROVIDERS = ["ollama", "anthropic", "openai", "openrouter", "azure_openai", "vllm", "bedrock"];
const BUILT_IN_PROVIDERS = new Set(["ollama", "anthropic"]);

export default function ModelsPage() {
  const {
    data: pins,
    loading: pinsLoading,
    error: pinsError,
    refetch: refetchPins,
  } = useApi(() => api.listModelPins(), []);
  const {
    data: defaults,
    loading: defaultsLoading,
    error: defaultsError,
  } = useApi(() => api.listRoleDefaults(), []);
  const [you, setYou] = useState("");

  const loading = pinsLoading || defaultsLoading;
  const error = pinsError ?? defaultsError;

  return (
    <div>
      <h2>Model configuration</h2>
      <p className="muted">
        Which provider/model runs bulk triage, escalation, and embeddings — local (Ollama, no
        per-finding cost), Anthropic, or bring your own: OpenAI (including the Codex/GPT family),
        OpenRouter, vLLM, Azure OpenAI, a self-hosted server — any name, any endpoint. Mirrors{" "}
        <code>kiyooo providers list/pin/test</code> 1:1. A pin is always a new row, never an edit —
        invariant #8: a model change is a change to detection logic, and needs its own record.
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

      {error && <div className="error-box">{error}</div>}
      {loading && <p className="muted">Loading…</p>}

      {defaults &&
        defaults.map((def) => {
          const pin = pins?.find((p) => p.role === def.role) ?? null;
          return (
            <RoleCard
              key={def.role}
              roleDefault={def}
              activePin={pin}
              you={you}
              onPinned={refetchPins}
            />
          );
        })}
    </div>
  );
}

function RoleCard({
  roleDefault,
  activePin,
  you,
  onPinned,
}: {
  roleDefault: RoleDefaultOut;
  activePin: ModelPinOut | null;
  you: string;
  onPinned: () => void;
}) {
  const effectiveProvider = activePin?.provider ?? roleDefault.provider;
  const effectiveModel = activePin?.model ?? roleDefault.model;

  const [showPinForm, setShowPinForm] = useState(false);
  const [testResult, setTestResult] = useState<ProviderTestResultOut | null>(null);
  const [testing, setTesting] = useState(false);
  const [testErr, setTestErr] = useState<string | null>(null);

  async function runTest() {
    setTesting(true);
    setTestErr(null);
    setTestResult(null);
    try {
      const result = await api.testProvider({
        provider: effectiveProvider,
        model: effectiveModel,
        endpoint_url: activePin?.endpoint_url ?? null,
        credential_ref: activePin?.credential_ref ?? null,
      });
      setTestResult(result);
    } catch (e) {
      setTestErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setTesting(false);
    }
  }

  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <h3 style={{ marginTop: 0, marginBottom: 4 }}>{ROLE_LABELS[roleDefault.role]}</h3>
          <p className="muted" style={{ marginTop: 0, marginBottom: 10, maxWidth: 520 }}>
            {ROLE_HELP[roleDefault.role]}
          </p>
        </div>
        <span className={`badge ${activePin ? "low" : "info"}`}>
          {activePin ? "pinned" : "settings (unpinned)"}
        </span>
      </div>

      <p style={{ fontSize: 14 }}>
        <code>{effectiveProvider}</code> / <code>{effectiveModel}</code>
      </p>
      {activePin && (
        <p className="muted" style={{ fontSize: 12 }}>
          pinned by {activePin.pinned_by} on {new Date(activePin.pinned_at).toLocaleString()} —{" "}
          {activePin.changelog_note}
          {activePin.endpoint_url && (
            <>
              <br />
              endpoint: <code>{activePin.endpoint_url}</code>
              {activePin.credential_ref && (
                <>
                  {" "}
                  · credential: <code>{activePin.credential_ref}</code>
                </>
              )}
            </>
          )}
        </p>
      )}

      <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
        <button className="secondary" disabled={testing} onClick={runTest}>
          {testing ? "Testing…" : "Test connection"}
        </button>
        <button className="secondary" onClick={() => setShowPinForm((s) => !s)}>
          {showPinForm ? "Cancel" : "Pin a different model"}
        </button>
      </div>

      {testErr && <div className="error-box">{testErr}</div>}
      {testResult && (
        <p className={testResult.ok ? "muted" : "error-box"} style={{ marginTop: 8 }}>
          {testResult.ok ? "OK" : "FAILED"} ({testResult.latency_ms}ms) — {testResult.detail}
        </p>
      )}

      {showPinForm && (
        <PinForm
          role={roleDefault.role}
          you={you}
          onPinned={() => {
            setShowPinForm(false);
            onPinned();
          }}
        />
      )}
    </div>
  );
}

function PinForm({
  role,
  you,
  onPinned,
}: {
  role: ModelPinRole;
  you: string;
  onPinned: () => void;
}) {
  const [provider, setProvider] = useState<string>("ollama");
  const [model, setModel] = useState("");
  const [digest, setDigest] = useState("");
  const [endpointUrl, setEndpointUrl] = useState("");
  const [credentialRef, setCredentialRef] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<ProviderTestResultOut | null>(null);
  const [testing, setTesting] = useState(false);

  const isBuiltIn = BUILT_IN_PROVIDERS.has(provider.trim().toLowerCase());
  const needsEndpoint = !isBuiltIn;

  async function testBeforePinning() {
    setTesting(true);
    setTestResult(null);
    setErr(null);
    try {
      const result = await api.testProvider({
        provider: provider.trim(),
        model: model.trim() || "(none entered yet)",
        endpoint_url: endpointUrl.trim() || null,
        credential_ref: credentialRef.trim() || null,
      });
      setTestResult(result);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setTesting(false);
    }
  }

  async function submit() {
    if (!provider.trim() || !model.trim() || !you.trim() || !note.trim()) {
      setErr("Provider, model, your email (above), and a changelog note are all required.");
      return;
    }
    if (needsEndpoint && !endpointUrl.trim()) {
      setErr(
        `'${provider.trim()}' isn't ollama/anthropic — it needs an Endpoint URL ` +
          "(bring-your-own-model has no default to fall back to).",
      );
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await api.createModelPin({
        role,
        provider: provider.trim(),
        model: model.trim(),
        digest: digest.trim() || model.trim(),
        pinned_by: you,
        changelog_note: note.trim(),
        endpoint_url: endpointUrl.trim() || null,
        credential_ref: credentialRef.trim() || null,
      });
      setModel("");
      setDigest("");
      setEndpointUrl("");
      setCredentialRef("");
      setNote("");
      onPinned();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid var(--border)" }}>
      <datalist id="known-providers">
        {KNOWN_PROVIDERS.map((p) => (
          <option key={p} value={p} />
        ))}
      </datalist>

      <div className="filters">
        <input
          list="known-providers"
          placeholder="provider — ollama, anthropic, openai, or anything"
          value={provider}
          onChange={(e) => setProvider(e.target.value)}
          style={{ width: 220 }}
        />
        <input
          placeholder="model, e.g. llama3.1:8b, gpt-5-codex, claude-sonnet-5"
          value={model}
          onChange={(e) => setModel(e.target.value)}
          style={{ width: 220 }}
        />
        <input
          placeholder="digest (optional — defaults to model name)"
          value={digest}
          onChange={(e) => setDigest(e.target.value)}
          style={{ width: 200 }}
        />
      </div>

      {needsEndpoint && (
        <div className="filters">
          <input
            placeholder="Endpoint URL — e.g. https://api.openai.com/v1 (required for a custom provider)"
            value={endpointUrl}
            onChange={(e) => setEndpointUrl(e.target.value)}
            style={{ width: 360 }}
          />
          <input
            placeholder="Credential env var — e.g. env:OPENAI_API_KEY (never a raw key)"
            value={credentialRef}
            onChange={(e) => setCredentialRef(e.target.value)}
            style={{ width: 280 }}
          />
        </div>
      )}

      <textarea
        placeholder="Changelog note — why this change (required, per invariant #8)"
        value={note}
        onChange={(e) => setNote(e.target.value)}
        rows={2}
        style={{ width: "100%", marginTop: 8 }}
      />

      <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
        <button
          className="secondary"
          disabled={testing || !provider.trim()}
          onClick={testBeforePinning}
        >
          {testing ? "Testing…" : "Test before pinning"}
        </button>
        <button disabled={busy} onClick={submit}>
          {busy ? "Pinning…" : "Pin"}
        </button>
      </div>

      {testResult && (
        <p className={testResult.ok ? "muted" : "error-box"} style={{ marginTop: 8 }}>
          {testResult.ok ? "OK" : "FAILED"} ({testResult.latency_ms}ms) — {testResult.detail}
        </p>
      )}
      {err && <div className="error-box">{err}</div>}
    </div>
  );
}
