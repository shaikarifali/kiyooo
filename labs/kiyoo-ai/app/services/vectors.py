"""`vectors` — a Chroma-shaped vector store.

Heartbeat + collection *names* only, matching kiyooo's `chroma` fingerprint
(body contains the literal key `"nanosecond heartbeat"`) and the
`exposed-vector-store` category. No embeddings, no documents, no query
endpoint — collection names alone carry the risk story (a store fronting
`customer_emails` is worse than one fronting `demo`), and that's exactly
what an unauthenticated real Chroma instance would leak for free.
"""

from __future__ import annotations

import time

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from ..common import LAB_NOTICE, decoy_headers

app = FastAPI(title="vectors (kiyoo-ai lab, Chroma-shaped)", docs_url=None, redoc_url=None)

_COLLECTIONS = ["support_kb", "hr_policies", "customer_emails"]


@app.get("/", response_class=HTMLResponse)
async def root() -> str:
    return (
        f"<h1>vectors (Chroma-shaped)</h1><p>{LAB_NOTICE}</p>"
        "<p>Try /api/v1/heartbeat and /api/v1/collections.</p>"
    )


@app.get("/api/v1/heartbeat")
async def heartbeat() -> JSONResponse:
    return JSONResponse({"nanosecond heartbeat": time.time_ns()}, headers=decoy_headers())


@app.get("/api/v1/collections")
async def collections() -> JSONResponse:
    return JSONResponse(
        [
            {"name": name, "id": f"lab-{i:04d}", "metadata": None}
            for i, name in enumerate(_COLLECTIONS)
        ],
        headers=decoy_headers(),
    )
