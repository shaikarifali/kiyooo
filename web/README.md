# kiyooo web

Next.js (App Router, TypeScript) frontend for kiyooo — Stage 10.
Talks to the FastAPI backend in `../kiyooo/api/` over plain `fetch`; no
server-side auth or session handling yet (the API itself has none — see
`kiyooo/api/deps.py`).

## Pages

In the design's priority order:

1. `/` — change feed (landing page: "what's new since yesterday")
2. `/triage`, `/triage/[id]` — triage queue + finding detail (verdict,
   reasoning, evidence, agree/disagree)
3. `/assets`, `/assets/[id]` — asset explorer + ownership + related-edges
   view
4. `/coverage` — coverage & orphan-asset report
5. `/categories` — category editor with a live "what would this match"
   preview (calls the same `evaluate_block` the CLI's `categories test`
   and live detection use — no separate reimplementation)
6. `/dashboard` — cost/agreement dashboard

## Running

```sh
npm install
cp .env.local.example .env.local   # point at your kiyooo API, defaults to localhost:8000
npm run dev
```

Requires `kiyooo serve` running (or `uvicorn kiyooo.api.app:app`) and a
real Postgres behind it — the backend has no in-memory fallback.

## Verifying

```sh
npm run typecheck   # tsc --noEmit
npm run lint        # eslint
npm run build       # next build (production build + type check)
```
