# kiyooo CLI reference

Every command below is real — pulled from `kiyooo --help` / `kiyooo <command> --help`
against the actual code, not written from memory. If this drifts from what `--help`
prints, `--help` is right and this file needs a re-sync.

See `README.md` first for setup (`uv sync`, `make dev`, `.env`) and the
**"What each command actually does to the network"** table — that table is the
safety reference; this file is the workflow reference. Don't skip it before
running anything with `--active`.

## Contents

- [0. First run](#0-first-run)
- [1. Scope: organizations, seeds, exclusions](#1-scope-organizations-seeds-exclusions)
- [2. Scan](#2-scan)
- [3. Detect, Triage, Review](#3-detect-triage-review)
- [4. Route](#4-route)
- [5. Change tracking: diff, events](#5-change-tracking-diff-events)
- [6. Ingest external findings](#6-ingest-external-findings)
- [7. Enrichment & asset queries](#7-enrichment--asset-queries)
- [8. Categories](#8-categories)
- [9. Eval & feedback loop](#9-eval--feedback-loop)
- [10. Ops: metrics, audit, serve](#10-ops-metrics-audit-serve)
- [11. A full walkthrough, start to ticket](#11-a-full-walkthrough-start-to-ticket)

Every `<name>` command that manages several things (`org`, `seed`, `exclusion`,
`route`, `assets`, `events`, `categories`, `ingest`, `eval`, `skills`, `metrics`,
`audit`, `feedback`) is a group — run `kiyooo <name> --help` to list its
subcommands, or `kiyooo <name> <subcommand> --help` for that one's exact flags.

---

## 0. First run

```bash
uv sync
cp .env.example .env
make dev                 # Postgres/Redis/MinIO up + migrations
uv run kiyooo doctor      # confirms DB/redis/minio/LLM/org-context are all reachable and valid
```

`doctor` sends no packets to any target — it only checks your own infrastructure and
that `org-context.example/` (or `KIYOOO_ORG_CONTEXT_PATH`) parses cleanly. Run it
first, every time something else fails in a confusing way.

---

## 1. Scope: organizations, seeds, exclusions

This is the DB-backed alternative to hand-editing `scope.yaml` — useful once you're
tracking more than one org, or want seeds added/audited without a git commit each
time. **`scope.yaml` still works on its own** — everything below is additive, opted
into per-scan with `--org`, never a replacement.

```bash
# create an org — third_party always forces active scanning off, refused if you
# try to override it:
kiyooo org create acme --name "Acme Corporation" --created-by you@acme.example

# a subsidiary:
kiyooo org create acme-labs --name "Acme Labs Ltd" \
  --parent acme --relationship subsidiary --created-by you@acme.example

# see the tree:
kiyooo org list --tree
```

Add seeds — one kind flag per call, they don't compose:

```bash
kiyooo seed add --org acme --domain acme.example --added-by you@acme.example
kiyooo seed add --org acme --wildcard "*.acme.example" --added-by you@acme.example
kiyooo seed add --org acme --cidr 203.0.113.0/24 --added-by you@acme.example
kiyooo seed add --org acme --asn AS64512 --added-by you@acme.example

# carve out an exception within an otherwise-included org:
kiyooo seed add --org acme --domain vendor-hosted.acme.example --exclude \
  --added-by you@acme.example --note "shared hosting, not ours"

kiyooo seed list --org acme
kiyooo seed disable <seed-id>       # soft-disable, never deleted
```

Every kind flag: `--domain` `--wildcard` `--subdomain` `--url` `--ip` `--cidr`
`--asn` `--cloud-account` `--github-org` `--saas-tenant` `--brand-term`
`--email-domain`. The last three (`github-org`/`saas-tenant`/`brand-term`) are
stored but not yet checkable by ScopeGuard — no code path resolves them to a
network target yet.

Exclusions — global (no `--org`, applies to every org) or scoped to one:

```bash
kiyooo exclusion add --domain internal-test.acme.example --reason "always excluded" \
  --source shipped_default
kiyooo exclusion add --org acme --cidr 198.51.100.0/24 --reason "vendor's shared range"
kiyooo exclusion list --org acme     # shows that org's own + every global one
kiyooo exclusion list                # global only
```

Exclusion always wins over any include, at every layer — a seed's own `--exclude`,
an org-level exclusion, and a global exclusion all deny the same way.

**What `--org` does and doesn't do yet:** it merges that org's seeds/exclusions
into `ScopeGuard`'s domain/wildcard/cidr/asn/cloud-account checks, and requires
the org's own `active_scanning_allowed` (forced `false` for `third_party`, always)
on top of `scope.yaml`'s own active-scan gates. It does **not** yet enforce
per-seed `verified`/`active_scan_allowed` overrides, expand `github_org`/
`saas_tenant`/`brand_term` seeds into anything, or score attribution — that's
`kiyooo-easm-standalone.md`'s later build items (2–4), not built yet.

---

## 2. Scan

```bash
kiyooo scan --explain                                   # what every adapter does, no network touched
kiyooo scan --seeds seeds.txt --dry-run                  # prints commands, runs nothing, ScopeGuard not even consulted
kiyooo scan --seeds seeds.txt                             # passive only (default --profile)
kiyooo scan --seeds seeds.txt --profile standard          # RUNS the httpx/tlsx probe stage, but see below
kiyooo scan --seeds seeds.txt --profile deep --active      # adds naabu portscan + katana crawl + nuclei — needs scope.yaml's active_scanning_enabled+attestation
kiyooo scan --seeds seeds.txt --org acme                  # merges acme's DB seeds/exclusions into this run's ScopeGuard
```

`seeds.txt` is a newline-delimited list of hostnames/IPs (`#` comments allowed).
`scan` prints a `scan_run_id` (a UUID) — every following command in this
pipeline needs it.

**`--profile` picks which stages run; `--active` is what lets any of the
packet-sending ones actually succeed.** Confirmed live: `--profile standard`
without `--active` still runs the `httpx`/`tlsx` probe stage, but every check
comes back `DENY` from `ScopeGuard` (`0 evidence, 0 allowed / N denied` in the
summary table) — safely denied, not silently skipped. `--active` alone isn't
enough either: `scope.yaml`'s `active_scanning_enabled`+`attestation`, and (if
`--org` is given) that org's own `active_scanning_allowed` all have to agree.
A freshly `org create`d org defaults to passive-only (`active_scanning_allowed`
is `false` unless you pass `--active-scanning-allowed` at creation) — this is
deliberately fail-closed, not a bug to work around.

---

## 3. Detect, Triage, Review

```bash
kiyooo detect --scan-run <id>                 # evaluates every enabled category, applies controls.yaml suppression
kiyooo triage --scan-run <id>                 # LLM adjudication pass over every NEW finding
kiyooo triage --scan-run <id> --active         # allows Stage 6 verification tools to send real packets
kiyooo triage --scan-run <id> --active --org acme   # same --org rule as scan — needed if the scan that found this used --org
```

`detect` never calls a model — pure predicate evaluation against evidence,
same engine `kiyooo categories test` uses. `triage` is where the LLM runs;
without `--active`, any verdict that would need to send a real packet to
confirm stays `needs_human` instead.

```bash
kiyooo review <finding-id> --verdict true_positive \
  --rationale "confirmed via console access" --reviewer you@acme.example
```

`--verdict` is one of `true_positive | false_positive | not_exploitable |
needs_human`. This is also what the web UI's Agree/Disagree buttons call —
same effect either way.

---

## 4. Route

```bash
kiyooo route run --scan-run <id>           # resolves owner+SLA, drafts/files tickets per category autonomy level
kiyooo route approvals list                # pending drafts — nothing here has been sent yet
kiyooo route approvals send <approval-id> --reviewer you@acme.example   # marks the finding ROUTED (invariant #6)
kiyooo route approvals reject <approval-id> --reviewer you@acme.example
kiyooo route close <ticket-id>              # moves the finding to verification_pending, not straight to fixed
kiyooo route recheck --scan-run <id>        # re-runs detect for pending findings; clears them to fixed or flips to regressed
kiyooo route escalate                       # sweeps tickets past SLA, marks escalated (idempotent, safe to cron)
kiyooo route digest --hours 24              # change events + newly-routed TPs, posted to Slack if configured, printed either way
```

Closing a ticket never marks a finding `fixed` by itself — `route recheck` against
a fresh scan is the only thing that does, and only if the category no longer
matches.

---

## 5. Change tracking: diff, events

```bash
kiyooo diff --since <scan-run-id-or-ISO-timestamp>
kiyooo events handle <new-asset-value> --kind deploy            # one-asset targeted scan → detect → triage → route, in one process
kiyooo events handle <new-asset-value> --kind deploy --active    # same authorization gates as `scan --active`
```

`events handle` is the fast path a CI/CD deploy webhook or cloud-resource-created
event would call — no discovery stage, just the one asset straight through the
pipeline. `--kind` is informational (`dns_record | cloud_resource | repo | deploy`).
It doesn't take `--org` — that's only on `scan` and `triage` so far.

---

## 6. Ingest external findings

```bash
kiyooo ingest run --source tenable --since 2026-08-01
kiyooo ingest run --file findings.csv --format csv \
  --csv-asset-col Host --csv-issue-type-col Type --csv-asset-type tcp_service
kiyooo ingest run --file scan.jsonl --format nuclei
kiyooo ingest unmapped     # vendor issue types with no vendor_mapping.yaml entry — a backlog, not a silent drop
```

Severity always comes from kiyooo's own category match via `vendor_mapping.yaml`,
never inherited from the vendor's own rating.

`mandiant`/`tenable` are hand-written adapters. For any other REST/JSON-emitting
ASM/VM tool (Qualys, Wiz, or an internal one), there's a generic, config-driven
connector — no code change to onboard one. See
`docs/ingest-source-config.example.yaml` for the config shape, or configure it
through the web UI's **Ingest** page:

```bash
kiyooo ingest sources add --name "Prod Qualys tenant" --config my-source.yaml
kiyooo ingest sources list
kiyooo ingest sources sync --id <source-id>
```

---

## 7. Enrichment & asset queries

```bash
kiyooo enrich --iac-repo /path/to/infra --iac-manifest main.tf --codeowners /path/to/CODEOWNERS
kiyooo enrich --skip-cloud    # skip AWS lookups even if credentials are available

kiyooo assets query 'type=http_service' 'is_active=true'    # ANDed field=value / field!=value clauses
kiyooo assets orphans                        # active, no ownership resolution >=0.8 confidence
kiyooo assets disputed-ownership              # top two ownership sources disagree, both >=0.8 — needs a human
kiyooo assets decommission-candidates         # reachable, unowned, unchanged for 3 scans — a lead list, never automatic
```

---

## 8. Categories

```bash
kiyooo categories test     # runs every category's .cases.yaml should/should-not-match fixtures — pure, no DB, no LLM
kiyooo categories lint     # every predicate name referenced actually exists in detect/predicates.py
```

Run both after editing anything under `org-context.example/categories/` — same
checks CI would run.

---

## 9. Eval & feedback loop

```bash
kiyooo eval run --provider ollama --model llama3.1:8b    # labeled corpus through one model's bulk pass — precision, recall, cost, latency. Calls a REAL model.
kiyooo feedback agreement        # model/human agreement rate per (category, model, prompt_version)
kiyooo feedback promote --dry-run   # preview only — omit --dry-run to actually open a suppressions.yaml PR
kiyooo skills list                # loads org-context/skills/*/SKILL.md, fails loudly on a parse error
```

`eval run` is the one command in this whole reference that calls a real LLM
provider outside the normal triage path — never run automatically, never part
of the test suite. The corpus shipped in `tests/eval/corpus/` is illustrative,
not a real accuracy benchmark.

---

## 10. Ops: metrics, audit, serve

```bash
kiyooo metrics report                                    # product-health metrics — treat a worsening trend as a release blocker
kiyooo audit export --output audit.json --hours 168        # dumps ScopeGuard's audit_log to JSON, for a SIEM or compliance review
kiyooo serve                                     # FastAPI backend, :8000 by default, OpenAPI at /openapi.json
kiyooo serve --port 8100 --reload                # dev: custom port + auto-reload
```

No auth on the API yet (`kiyooo/api/deps.py`) — run it behind a trusted network.

---

## 11. A full walkthrough, start to ticket

```bash
kiyooo doctor

kiyooo org create acme --name "Acme Corporation" --created-by you@acme.example
kiyooo seed add --org acme --domain acme.example --added-by you@acme.example
kiyooo seed add --org acme --wildcard "*.acme.example" --added-by you@acme.example

echo acme.example > seeds.txt
kiyooo scan --seeds seeds.txt --org acme --profile standard
# -> prints a scan_run_id, call it $RUN

kiyooo detect --scan-run $RUN
kiyooo triage --scan-run $RUN
kiyooo route run --scan-run $RUN

kiyooo route approvals list        # see what's drafted before anything sends
```

Or watch it in the web UI instead of the terminal: `kiyooo serve` (or the
`scripts/kiyoo` launcher — see `README.md`), then `web/`'s dashboard shows the
same change feed, triage queue, and routed tickets live.
