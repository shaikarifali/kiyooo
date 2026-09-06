"""`notebook` — a Jupyter-shaped server, no token.

Matches kiyooo's `jupyter` fingerprint (body contains "jupyter"). No
kernel exists behind this — there is no code-execution path here, ever
(a real Jupyter server with
no token is a code-execution primitive, so this decoy must never become
one, even by accident).
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ..common import LAB_NOTICE, decoy_headers

app = FastAPI(title="notebook (kiyoo-ai lab, Jupyter-shaped)", docs_url=None, redoc_url=None)


@app.get("/")
async def root() -> RedirectResponse:
    # Real Jupyter redirects / -> /tree the same way.
    return RedirectResponse(url="/tree")


@app.get("/api")
async def api_root() -> JSONResponse:
    return JSONResponse({"version": "7.0.0-lab"}, headers=decoy_headers())


@app.get("/tree", response_class=HTMLResponse)
async def tree() -> str:
    return (
        "<title>Home Page - Select or create a notebook - Jupyter Notebook</title>"
        f"<h1>Jupyter Notebook</h1><p>token: null</p><p>{LAB_NOTICE}</p>"
        "<p>No kernel is attached to this decoy. There is no execution path here.</p>"
    )
