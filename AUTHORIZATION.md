# Authorization

kiyooo refuses to run an active scan — anything that sends a packet directly to a
target's own infrastructure — unless authorization is on record. This is
guardrail #1 and it is enforced in code, not just in this document:
`ScopeGuard` (`kiyooo/recon/scope.py`) checks `scope.yaml` before every single
target, on every single active-capable adapter call, every time — not once at
scan start.

## What "active" means here

An adapter is `is_active = True` if it sends a request, probe, or handshake
directly to the target's own service. `kiyooo scan --explain` prints the exact
list; as of Stage 1 that's `naabu`, `httpx`, `tlsx`, `katana`, and `nuclei`. Every
other adapter (`subfinder`, `crtsh`, `amass`, `dnsx`, `shodan`, `censys`) queries a
third-party data source or resolver *about* the target and never contacts it.

## What's required before `--active` works

`scope.yaml` must have all three of:

```yaml
active_scanning_enabled: true
authorized_by: "<name or role of the person who approved this>"
authorization_date: "<date approved, ISO 8601>"
attestation: true
```

If any of these is missing, `kiyooo scan --active` refuses to start — checked
twice: once by `ScopeConfig`'s Pydantic validator at config-load time (a
misconfigured `scope.yaml` fails to even parse), and again explicitly by the CLI
before the run starts. `attestation: true` is a statement that the three fields
above are true, not a formality — don't set it without actually having
authorization.

Third-party scope
cannot set `active_scanning_enabled: true` at all — this is enforced structurally
in `ScopeConfig`, not left to policy. Scanning infrastructure you don't own is
passive-only, full stop.

## What happens at scan start

When `--active` is authorized, the CLI prints a banner before anything runs:

```
ACTIVE SCAN AUTHORIZED
  org: <org_name>
  authorized_by: <authorized_by>
  authorization_date: <authorization_date>
  attestation: True
```

This is the same information that goes on record — every `ScopeGuard` decision
for the run (`ALLOW`, `DENY`, `REQUIRES_CONFIRM`) is written to the append-only
`audit_log` table, exportable, before the corresponding packet is ever sent.

## What is never authorized, regardless of `scope.yaml`

Per CLAUDE.md invariant #1, no configuration turns these on:

- Credential submission or default-password attempts
- Parameter fuzzing or path brute-forcing
- Any write (POST/PUT/DELETE) to a target
- `nuclei` templates tagged `dos`, `intrusive`, or `fuzz` (excluded unconditionally
  — see `kiyooo/recon/adapters/nuclei.py`)

If a request needs one of these, the answer is no, and no `scope.yaml` field
changes that.
