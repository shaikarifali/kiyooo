"""`qdrant` — a Qdrant-shaped vector store.

Matches kiyooo's `qdrant` fingerprint (`"title":\\s*"qdrant`) and the
`exposed-vector-store` category (`port_in: [6333]` in the real deployment
— bind this service to 6333 in compose). Collection names only, same rule
as `vectors.py`.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from ..common import decoy_headers

app = FastAPI(title="qdrant (kiyoo-ai lab)", docs_url=None, redoc_url=None)


@app.get("/")
async def root() -> JSONResponse:
    return JSONResponse(
        {"title": "qdrant - vector search engine", "version": "1.9.0-lab"},
        headers=decoy_headers(),
    )


@app.get("/collections")
async def collections() -> JSONResponse:
    return JSONResponse(
        {
            "result": {
                "collections": [
                    {"name": "product_embeddings"},
                    {"name": "internal_docs"},
                ]
            },
            "status": "ok",
            "time": 0.0001,
        },
        headers=decoy_headers(),
    )
