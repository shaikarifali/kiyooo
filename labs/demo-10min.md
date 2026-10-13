# The 10-minute demo

The standard "someone stopped at the booth and has a few minutes" version.
Assumes the **prep** below already happened — nothing in the 10 minutes
itself waits on a slow step, and nothing in it runs the full active-scan
pipeline live. That pipeline works, but it's slow and noisy enough
(next section) that it does not belong in front of an audience yet.

For the "someone is literally walking past, you have 90 seconds" case,
see acmecorp's own README — that version stays as-is, it's the fastest
one and doesn't need kiyoo-ai in it.

## Prep (do this before your shift starts, never live)

Three real things to know before you run this, all found by actually
running the full chain against both labs, not assumed from the docs:

1. **Full recon (`amass`/`subfinder`) is genuinely slow against `.lab`
   domains** — several minutes per run, sometimes 6+, because they're
   real passive-OSINT tools querying real external sources that return
   nothing for a fake TLD. Never run a full scan live.
2. **Active scanning needs `--active`, plus `active_scanning_enabled`
   and `attestation` in `scope.yaml`.** Without it, ScopeGuard denies
   the httpx/tlsx probes — meaning almost nothing gets detected at all,
   since most categories need to read an HTTP response to fingerprint
   the service. `org-context.example/scope.yaml` already has this
   turned on for `*.acmecorp.lab`/`*.kiyoo-ai.lab` specifically (both
   synthetic, first-party, localhost-only) — leave it off for anything
   that isn't your own lab.
3. **A PATH collision**: this repo's own Python dependencies install a
   console script literally named `httpx` into the venv — same name as
   ProjectDiscovery's real recon binary. Whichever one PATH finds first
   wins, and a venv's own `bin/` is normally first. The command below
   pins `/usr/local/bin` (and `~/go/bin`, where `naabu` lives if you
   installed it via `go install`) ahead of the venv, which fixes it.
   Do this every time you run an active scan from a shell, not just once.

```bash
kiyoo-labs                          # both labs + kiyoo-range, one command
KIYOOO_API_PORT=8100 kiyoo          # the real tool: API :8100, UI :3000
export PATH="/usr/local/bin:$HOME/go/bin:$PATH"   # see point 3 above

# once per booth day, NOT during a conversation — full baseline scan:
uv run kiyooo scan --seeds labs/acmecorp/seeds.txt --profile standard --active
uv run kiyooo scan --seeds labs/kiyoo-ai/seeds.txt --profile passive --active
# note the two scan_run ids these print, then:
uv run kiyooo detect --scan-run <acmecorp-id>
uv run kiyooo detect --scan-run <kiyoo-ai-id>
uv run kiyooo triage --scan-run <acmecorp-id>
uv run kiyooo triage --scan-run <kiyoo-ai-id>

labs/scenarios/undo.sh 2>/dev/null      # acmecorp: reset the drift scenario
labs/kiyoo-ai/scenarios/undo.sh         # kiyoo-ai: reset its drift scenario
```

One more honest caveat: every lab and the real tool all bind to
`127.0.0.1` on this one machine, so a port-scanning stage (`naabu`)
scanning a `.lab` hostname's resolved IP can pick up *other* local
services sharing that same loopback address — not just the intended
target. Skim the finding list after your baseline scan for anything
that clearly isn't one of the labs' planted assets before you trust it
at face value; this is a property of demoing everything on one laptop,
not a product bug.

Confirm before you walk away from setup: the web UI's triage queue
(`localhost:3000/triage`) shows real findings, not an empty list or a
"Failed to fetch" error.

## The 10 minutes

**1. Change feed (1 min)** — `localhost:3000` (the landing page).
*"Here's everything new since the last scan."* Point at a couple of
recent change events, don't dwell.

**2. A correctly suppressed finding (2 min)** — open the
`exposed-admin-panel` finding on `admin.acmecorp.lab`. It's **not** in
the triage queue. Show why: the `sso_gateway` control, the real 302
redirect chain to a `login.microsoftonline.com`-shaped URL it matched.
*"This is the finding a lesser tool would page someone about at 2am."*

**3. Clustering (1 min)** — open the `expired-cert` finding. 40 vhosts,
one shared expired cert, one `cluster_id`, one ticket. *"Three vendor
tools would have reported this 40 times."*

**4. The actual headline: blast radius, not just exposure (3 min)** —
open `mcp-docs` and `mcp-ops` side by side in the triage queue. Same
category (`exposed-mcp-server`), same kind of exposure — no auth in
front of either. Different severity: `mcp-docs` lands **medium**
(read-only catalog), `mcp-ops` lands **critical**. Point at the
reasoning text citing the actual tool names: `query_customer_db`,
`send_email`, `run_shell`, `read_file`. *"It didn't just find an
open MCP server — it read the tool catalog and reasoned about what
those tools can actually reach."* Then open `mcp-legacy`
(`mcp-tool-poisoning-risk`) — a tool description carrying hidden
instruction text aimed at whatever LLM reads it, flagged, not followed.

**5. Watch it happen — the honest live moment (2 min)** — not the full
pipeline (too slow to run live, see prep), but the underlying drift is
real and instant, and that's worth showing:

```bash
curl -s http://internal-tools.kiyoo-ai.lab:8000/    # before: 403
./labs/kiyoo-ai/scenarios/dev-exposes-prod.sh
curl -s http://internal-tools.kiyoo-ai.lab:8000/    # after: same catalog as mcp-ops
```

Narrate: *"That's not a mockup toggling — that's a real service's
response changing, live, right now. A CI/CD deploy webhook would call
`kiyooo events handle` on exactly this the moment it happened."* Then
show the **already-triaged** version of this exact finding sitting in
the triage queue from this morning's baseline run — same reasoning,
same critical severity, just not conjured in front of them. Reset for
the next person: `./labs/kiyoo-ai/scenarios/undo.sh`.

**6. Close (1 min)** — `uv run kiyooo ingest unmapped`. Show the ~190
rows of vendor noise sitting there as a visible work item, never
silently dropped, never silently surfaced as 190 pages in someone's
queue either.

## If something's already broken when they walk up

Don't debug live. Fall back to `kiyoo-range` (`localhost:9900`) — every
category, always up, no scan dependency, still visually consistent with
the real tool. *"And here's the full range of what it covers"* is a
completely legitimate pivot, not a downgrade.
