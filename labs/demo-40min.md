# The 40-minute demo

The full-session version — someone sat down, wants to actually
understand the tool, and you have room to go deep. This is
`demo-10min.md` first, then the material below. Do the 10-minute prep
(both labs up, real tool up, a baseline scan/detect/triage already run
that morning) before this starts too — the only thing that's allowed to
run live in this version is a fresh full scan, and only because 40
minutes has slack to absorb it; everything else stays pre-populated for
the same reason it does in the 10-minute version.

## 0. Run `labs/demo-10min.md` in full (10 min)

Same six steps, same pace. Don't rush it just because you have more
time after — it's the strongest material and deserves the room it
already has.

## 1. Do a scan from scratch, live (8–15 min — budget generously)

This is the one place a full `kiyooo scan` runs live — start it, then
talk over it, don't wait on it in silence. Timed live end-to-end once:
6+ minutes is realistic, not a worst case, so don't promise "under 10
minutes" out loud — narrate confidently for as long as it takes instead.

Needs the same two things `demo-10min.md`'s prep covers: `--active`
(plus `scope.yaml`'s `active_scanning_enabled`/`attestation`, already
on for both labs), and `/usr/local/bin`/`~/go/bin` ahead of this repo's
venv on PATH — a Python dependency here installs its own console script
named `httpx`, same name as the real recon binary; whichever the shell
finds first wins.

```bash
export PATH="/usr/local/bin:$HOME/go/bin:$PATH"
uv run kiyooo scan --seeds labs/kiyoo-ai/seeds.txt --profile standard --active
```

While it runs (the discovery stage genuinely takes several minutes —
real `amass`/`subfinder` passive OSINT against every seed, that's not a
demo artifact, it's what passive recon actually costs), narrate the
architecture, not the wait:

- **ScopeGuard, not the planner, is the enforcement point.** No adapter
  sends a packet to a target without a `scope.yaml`-checked `ALLOW` and
  an `audit_log` row — walk through `org-context.example/scope.yaml`,
  show `*.kiyoo-ai.lab` sitting there as an explicit wildcard, same
  pattern any real org's domains would use.
- **Passive by default, active behind three separate gates**: a config
  flag, a CLI `--active` flag, and a signed attestation in
  `scope.yaml`. Show `--active` refused without all three.
- **The LLM has no authority.** It drafts a verdict with cited evidence
  IDs; a validator rejects anything uncited. It never closes a finding,
  never auto-suppresses a critical, never sends a packet.

One thing to know before you narrate it as clean: every lab and the
real tool share `127.0.0.1` on this one laptop, so the port-scan stage
can surface *other* local services on that same loopback address, not
just the lab's planted assets. If an unfamiliar finding shows up,
that's why — check it before presenting it as a lab result.

When the scan finishes, run detect and triage on it live — these are
fast (no external OSINT, just predicate evaluation + one bulk LLM
pass) — and open the new `scan_run`'s findings in the triage queue.
This is the moment they watch the exact pipeline from step 4 of the
10-minute version happen from a cold start, on a target they just saw
you name in the terminal.

```bash
uv run kiyooo detect --scan-run <id>
uv run kiyooo triage --scan-run <id>
```

## 2. The category editor — "what would this match" (5 min)

`localhost:3000/categories`. Pick a category (`exposed-mcp-server` is
the natural choice given what you just showed). Paste a synthetic
asset + evidence payload, run the live preview — this runs the exact
same predicate evaluator as `kiyooo categories test` and live
detection, not a separate reimplementation. Change one field (drop
`run_shell` from the tool list, say) and re-run it to show the
severity move. *"This is the same evaluator that just ran against the
real lab a minute ago — nothing here is a mockup."*

## 3. Routing and human approval (5 min)

```bash
uv run kiyooo route run --scan-run <id>
uv run kiyooo route approvals list
```

Show a drafted ticket sitting in `approvals list` — not sent. This is
invariant #6: **a human approves outbound**, always, until a category
is explicitly promoted up the autonomy ladder. Walk through what a
drafted ticket actually contains (assignee/cc resolved from
`ownership` + `teams.yaml`, SLA, the cited evidence) before you'd ever
approve it.

## 4. Coverage and the dashboard (5 min)

`localhost:3000/coverage` — what fraction of known assets have a
recent scan touching them; this is the "are we actually looking
everywhere" answer, not just "here's what we found."

`localhost:3000/dashboard` — model/human agreement per
category+model+prompt_version, and LLM spend per scan run. *"This is
the honest answer when someone asks 'how do you know it works' — not a
claim, a number that updates every time a human overrides a verdict."*

## 5. Asset explorer + noise, in full (5 min)

`localhost:3000/assets` — browse what's actually been discovered
across both labs. Then:

```bash
uv run kiyooo ingest unmapped
```

Full walkthrough this time, not the one-liner from the 10-minute
version: show a few of the ~190 unmapped rows, explain why they're
noise (vendor scanner categories with no `category:` mapping yet) and
why that's a visible backlog item, not a silent drop and not a queue
someone has to page through.

## Close: reset for the next person

```bash
labs/scenarios/undo.sh 2>/dev/null
labs/kiyoo-ai/scenarios/undo.sh
```

If you ran a live scan in step 1, its `scan_run`/findings stay in the
DB — that's fine, real usage looks like an accumulating history, not a
wiped slate between sessions. Only the drift-scenario toggles need
resetting.

## If you're asked something you didn't plan for

This is scripted material, not the limit of what the tool does. If a
question goes somewhere the script doesn't cover, say so honestly and
either show it live if it's quick, or take the question — a solo-built
tool that admits its edges is more credible at Black Hat than one that
claims to have none.
