# kiyoo-range — the interactive front door

Not a planted-asset lab like `acmecorp` or `kiyoo-ai` — this is the app
that ties every lab together into one thing you click through, organized
exactly around kiyooo's 23 shipped categories (13 infra + 10 AI, same
split as `org-context.example/categories/`). You never visit another
port or hostname: every HTTP-backed category's page embeds a **Live
view** iframe that's actually `kiyoo-ai`'s or `acmecorp`'s real decoy
page, reverse-proxied through kiyoo-range itself (`app/proxy.py` —
same-origin, no CORS wall, no cross-port navigation). Below that, a
**Fetch live evidence** button calls this app's own backend for the raw
status/headers/body dump. Categories with no HTTP surface
(`exposed-database`, a raw TCP handshake) only show the evidence panel —
there's nothing to embed a page for.

Four categories had no planted asset anywhere before this app existed:
`exposed-devops-console`, `subdomain-takeover`, `known-exploited-cve`,
`shadow-saas-tenant`. Those are served directly out of `app/decoys.py`
(see that file's docstring — each one checked against the exact
`detect:` regex in `org-context.example/categories/00-core/`, not
eyeballed).

**Offline previews (`app/evidence.py`'s `_offline_fallback`):** the other
19 categories need `kiyoo-ai` or `acmecorp` running for genuinely live
evidence. When that lab isn't up, the fetch doesn't just fail — each of
those 19 `Demo`s in `app/catalog.py` carries an `offline_example`: a real
response body copied out of that lab's own service source (`labs/kiyoo-ai/
app/services/*.py`, `labs/acmecorp/nginx-conf/*.conf`), not invented. The
page shows it with a clearly-worded `OFFLINE PREVIEW` banner — the point
is that a reviewer with neither backing lab running still sees a concrete,
honest example on every one of the 23 cards, never a bare "connection
refused." Run the real lab (`kiyoo-labs ai` / `kiyoo-labs acmecorp`) and
the same button fetches genuinely live evidence instead — `data.offline`
in the `/api/evidence/<slug>` JSON response tells you which one you got.

**Honesty note:** the 4 local decoys and the offline-preview text were
checked by hand against each service's real source in this session; the
*live*, non-offline path (this app's proxy actually reaching a running
`kiyoo-ai`/`acmecorp`) needs both those labs' Docker stacks up, which
this sandbox can't do (no Docker daemon here) — rehearse that path once
before relying on it, same rule as every other lab's README.

## Run

Standalone Python process, not a container (unlike the other two labs) —
`kiyoo-labs` (or `kiyoo-labs range`) starts it with the repo's own `.venv`
via `nohup`, same pattern `scripts/kiyoo` uses for the main API/web:

```bash
uv sync   # once, if you haven't — fastapi/uvicorn/httpx need to be in .venv
kiyoo-labs range
```

Or run it directly:

```bash
.venv/bin/python -m uvicorn app.main:app --app-dir labs/kiyoo-range --host 0.0.0.0 --port 9900
```

Open `http://localhost:9900/`. (Port 9900, not 9000 — 9000/9001 is kiyooo's own MinIO,
from the repo root `docker-compose.yml`.)

## What's here

| Path | What |
|---|---|
| `app/catalog.py` | The 23-category list — name, severity, summary, and exactly how to go get live evidence for each one |
| `app/decoys.py` | The 4 categories this app serves itself, with no other lab needed |
| `app/evidence.py` | Does the real fetch (HTTP GET/POST, or a raw TCP read for `exposed-database`) and normalizes the result for the page to render |
| `app/proxy.py` | Reverse-proxies `/proxy/<slug>/...` to the category's real decoy host, so the Live view iframe never leaves kiyoo-range's own origin/port |
| `app/main.py` | The FastAPI app: home page, one page per category (Live view iframe + evidence panel), `/api/evidence/<slug>`, `/proxy/<slug>/...` |

Standalone like the other labs: no import of the `kiyooo` package, just
fastapi/uvicorn/httpx.
