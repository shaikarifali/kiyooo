# acmecorp — the demo lab

PLAN.md §7 Stage 12: a fake org, in Docker Compose, planted to exercise
real shipped categories — and just as importantly, their false-positive
paths. Everything binds to `127.0.0.1` only. This is built to run on a
laptop with the wifi off.

**Honesty note, read this first:** these Compose/nginx/seed files were
authored and their individual pieces verified in isolation (the expired-
cert generator was run and its output checked with `openssl x509
-checkend`; the junk-findings CSV was run through kiyooo's real CSV
importer and confirmed to parse to 200 findings; every YAML file here was
parsed to confirm it's syntactically valid) — but the *full* `docker
compose up` -> `kiyooo scan` -> `kiyooo triage` -> `kiyooo route` chain
against all eight services has not been run end-to-end, because this
environment has no Docker daemon. **Rehearse this in full at least once
before you stand at a booth with it.** If a specific finding doesn't land
the way this README describes, that's the thing to fix first — the
categories and predicates it depends on are already unit- and fixture-
tested (`kiyooo categories test`), so a mismatch is almost certainly in
this lab's content (an nginx response shape, a missing `/etc/hosts`
entry), not in kiyooo's detection logic itself.

## Setup (once)

```bash
# kiyooo's own backing store must already be running:
make dev   # from the repo root — Postgres/Redis/MinIO for kiyooo itself

# Add the lab's fake hostnames to /etc/hosts (they don't resolve otherwise —
# there's no real DNS in an air-gapped demo):
sudo tee -a /etc/hosts <<'EOF'
127.0.0.1  staging.acmecorp.lab admin.acmecorp.lab leak.acmecorp.lab waf.acmecorp.lab app01.acmecorp.lab app02.acmecorp.lab app03.acmecorp.lab app04.acmecorp.lab app05.acmecorp.lab app06.acmecorp.lab app07.acmecorp.lab app08.acmecorp.lab app09.acmecorp.lab app10.acmecorp.lab app11.acmecorp.lab app12.acmecorp.lab app13.acmecorp.lab app14.acmecorp.lab app15.acmecorp.lab app16.acmecorp.lab app17.acmecorp.lab app18.acmecorp.lab app19.acmecorp.lab app20.acmecorp.lab app21.acmecorp.lab app22.acmecorp.lab app23.acmecorp.lab app24.acmecorp.lab app25.acmecorp.lab app26.acmecorp.lab app27.acmecorp.lab app28.acmecorp.lab app29.acmecorp.lab app30.acmecorp.lab app31.acmecorp.lab app32.acmecorp.lab app33.acmecorp.lab app34.acmecorp.lab app35.acmecorp.lab app36.acmecorp.lab app37.acmecorp.lab app38.acmecorp.lab app39.acmecorp.lab app40.acmecorp.lab
EOF

# Point kiyooo's bulk AND escalation model at a local Ollama and pull a
# small model before you're offline — this is what "make lab-demo" checks:
export KIYOOO_LLM_PROVIDER=ollama
export KIYOOO_ESCALATION_PROVIDER=ollama
ollama pull llama3.1:8b
```

## Running

```bash
make lab-demo    # air-gap check, then everything lab-up does
# or, if you're not checking for egress right now:
make lab-up

uv run kiyooo scan --seeds labs/acmecorp/seeds.txt --profile standard
uv run kiyooo detect --scan-run <id-printed-by-scan>
uv run kiyooo triage --scan-run <id>
uv run kiyooo route run --scan-run <id>
```

`make lab-reset` tears down and reseeds — PLAN.md's DoD is "under 60
seconds," which holds once Docker images are already pulled locally (the
very first run pulls ~six images and won't be fast; do that before you're
on conference wifi, not during).

## What's planted, and what it demonstrates

| Service | Port | Category | Outcome |
|---|---|---|---|
| `mysql-exposed` | 3306 | `exposed-database` | Critical TP |
| `staging-app` | 8081 | `exposed-nonprod-to-internet` | TP, downgraded to medium — the page says "seeded fixture data" and the triage hints tell the model to read that |
| `ollama` | 11434 | `exposed-inference-endpoint` | Critical TP — "lands with a Black Hat audience" per PLAN.md |
| `minio-public` (bucket `customer-invoices`) | 9500 | `exposed-cloud-storage` | TP — one planted `invoice.pdf`, publicly readable |
| `leaky-secret-app` (`/.env`) | 8082 | `leaked-secret` / `leaked-ai-api-key` | Critical TP, redaction path — the finding shows `[REDACTED:...]`, never the fixture key itself |
| `expired-cert-app` | 8443 | `expired-cert` | Critical TP, **clustering**: 40 vhosts, one shared expired cert, one `cluster_id`, one ticket |
| `sso-admin-panel` (`/admin`) | 8083 | `exposed-admin-panel` | **Correct FP** — real 302 redirect chain to a `login.microsoftonline.com`-shaped URL, suppressed by the `sso_gateway` control |
| `waf-app` (`/search`) | 8084 | `generic-web-cve` | **Severity reduced, not suppressed** — `cf-ray` header matches the `cloudflare_waf` control (`reduce_by: 1`); the SQL-error-shaped body is there for a real nuclei run's signature templates to match — see the config's own note on template-version dependence |
| 200 rows via `kiyooo ingest` | — | mostly unmapped | **The whole pitch, visibly** — `kiyooo ingest unmapped` shows ~190 rows of vendor noise with no category mapping (never silently dropped, never silently surfaced either); the ~10 that map land on `mysql-exposed` and collapse via fingerprint reconciliation into the *same* finding `kiyooo scan` already found there |

`weak-tls-version.yaml` (the decommissioned-TLS-1.0-host row) ships as a
category — `kiyooo categories test` covers it with fixtures — but isn't
planted as a live docker-compose asset here: forcing a genuine TLS
1.0-only handshake reliably needs a legacy openssl/nginx build, which is
too image-version-specific to guarantee sight-unseen. Add a
`legacy-tls-app` service (an older `nginx` image, `ssl_protocols TLSv1;`)
during rehearsal if you want this one live.

## Cloud posture demo (the web UI's `/cloud` page)

Prowler audits a *real* cloud account's control-plane API (see
`ingest/adapters/prowler.py`'s own docstring) — there's no fake HTTP
service to stand up in Docker Compose the way there is for
`exposed-database` or `exposed-cloud-storage` above. Two `ProwlerConfig`
fixtures ship here anyway (`seed/cloud-accounts/prod-aws.yaml`,
`staging-gcp.yaml`) so a visitor sees a populated Cloud posture page —
account cards, enable/disable, "last audited" — instead of an empty
one:

```bash
uv run kiyooo cloud accounts add --name prod-aws --config labs/acmecorp/seed/cloud-accounts/prod-aws.yaml
uv run kiyooo cloud accounts add --name staging-gcp --config labs/acmecorp/seed/cloud-accounts/staging-gcp.yaml
```

Both `credential_env` entries point at env vars that deliberately don't
exist in this lab, so clicking "Audit now" on either one produces a
clean `ProwlerRunError` ("prowler binary not found" or a credential
error), not a hang or a 500 — that's expected, and worth narrating at a
booth as the failure-visibility guarantee, not a bug. To get a *real*
live audit instead: point `prod-aws.yaml` at an actual AWS account (a
free-tier sandbox is enough — Prowler only reads, never writes) or a
local LocalStack container, and set the real env vars it names before
running `kiyooo cloud accounts add`. This exact path — env vars set,
`prowler` on `PATH`, real or LocalStack credentials — has not been
rehearsed end-to-end in this repo's own dev environment (no internet
egress to install/verify `prowler` here); confirm it once before you
promise a live Prowler run at the booth, same rehearsal rule as
everything else in this README.

## The three scripted runtimes

**90 seconds (someone walking past).** Have `kiyooo events handle` from
the drift scenario already run once before they arrive, and the triage
queue open in the web UI (`web/`, pointed at `kiyooo serve`) on the
`exposed-database` finding. Say: "This found a MySQL server anyone on the
internet could connect to, decided it was real without me telling it
what MySQL looks like, and drafted this ticket with the right person
already assigned — an inference model figured out who owns it." Point at
the reasoning text. Done.

**10 minutes (the standard Arsenal conversation).**
1. Show the change feed (`web/`'s landing page) — "here's everything new
   since the last scan."
2. Open the `exposed-admin-panel` finding on `admin.acmecorp.lab` and show
   it's **not** in the triage queue — it was suppressed, and show why:
   the `sso_gateway` control, the redirect chain evidence it matched.
   "This is the finding a lesser tool would page someone about at 2am."
3. Open the `expired-cert` finding and show 40 assets clustered into one
   ticket. "Three vendor tools would have reported this 40 times."
4. Run `labs/scenarios/dev-exposes-prod.sh` live — narrate while it runs:
   change event, triage, owner attribution, drafted ticket, under two
   minutes, offline.
5. Run `kiyooo ingest unmapped` and show the 190 rows of noise sitting
   there as a work item, not 190 pages in someone's queue.

**40 minutes (a full session).** All of the above, plus:
- The wrong-answer moment (below).
- `kiyooo metrics report` — the product-health metrics, and why
  `findings_surfaced_per_analyst_per_week` alone is a trap metric.
- The category editor's live preview (`web/`'s `/categories` page) —
  live-edit a predicate against the planted evidence and show the
  preview flip.
- `kiyooo eval run` against the illustrative corpus, and an honest caveat
  about what a real 100+-finding labeled corpus would take.

## The wrong-answer moment

Don't skip this — PLAN.md is explicit that a flawless demo reads as
dishonest to this audience, and the best-performing orgs in practice are
the ones that show their tool's limits, not just its wins.

1. Pick a finding the model got wrong — the easiest to stage is
   `shadow-ai-saas-tenant` or `shadow-saas-tenant` marked `true_positive`
   when it's actually a sanctioned, known tool (seed one deliberately if
   nothing naturally lands wrong in your rehearsal run).
2. `uv run kiyooo review <finding-id> --verdict false_positive --rationale "sanctioned Zendesk instance, confirmed with IT" --reviewer you@acmecorp.lab`
3. Repeat that exact rationale on four more findings sharing the same
   category (`kiyooo review` five times — Stage 8's promotion threshold is
   5) to trigger `kiyooo feedback promote`.
4. `uv run kiyooo feedback promote --dry-run` — show the proposed
   `suppressions.yaml` entry. "The model was wrong once. It won't be
   wrong about this specific thing again, and that's a PR a human
   reviews, not an autonomous decision."

## Air-gap check

`make lab-demo` refuses to start if `KIYOOO_LLM_PROVIDER` or
`KIYOOO_ESCALATION_PROVIDER` point at anything but `ollama`. This is a
config check, not a firewall — it catches the "I forgot to switch back
from Anthropic after testing" mistake, not a determined attempt to phone
home. Actually disable wifi before you present.
