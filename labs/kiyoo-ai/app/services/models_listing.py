"""`models` — an autoindex serving an unsafe-format model artifact
. Matches kiyooo's `unsafe-model-artifact` category
(`\\.(pkl|pt|pth|bin|h5|ckpt)([\"'<)\\s]|$)` against the directory-listing
HTML). The artifact itself starts with a pickle magic header so a byte
sniffer would agree it *looks* like a pickle — but it is a few KB of
random bytes after that, not a real pickle stream. It is never
deserialized by anything in this lab or by kiyooo itself.
"""

from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, Response

from ..common import LAB_NOTICE, decoy_headers

app = FastAPI(title="models (kiyoo-ai lab)", docs_url=None, redoc_url=None)

_ARTIFACT_NAME = "sentiment-v2.pkl"
# Real pickle protocol-4 magic (0x80 0x04) followed by non-opcode filler —
# looks right to a byte sniffer, fails to unpickle, never attempted here.
_ARTIFACT_BYTES = b"\x80\x04" + os.urandom(4096)


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return (
        f"<h1>Index of /</h1><p>{LAB_NOTICE}</p>"
        f'<ul><li><a href="{_ARTIFACT_NAME}">{_ARTIFACT_NAME}</a></li></ul>'
    )


@app.get(f"/{_ARTIFACT_NAME}")
async def artifact() -> Response:
    return Response(
        content=_ARTIFACT_BYTES,
        media_type="application/octet-stream",
        headers=decoy_headers(),
    )
