"""`chat` — a public chatbot claiming tool access.

Matches kiyooo's `open_webui` fingerprint and the
`public-chatbot-excessive-agency` category (body matches
`open webui|anythingllm|dify|flowise|langflow|chainlit`). The canned reply
*claims* internal tool access to give triage corroborating evidence to
reason about — it never actually calls anything. There is no tool
integration behind this endpoint.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from ..common import LAB_NOTICE, decoy_headers

app = FastAPI(title="chat (kiyoo-ai lab, Open WebUI-shaped)", docs_url=None, redoc_url=None)

_CANNED_REPLY = (
    "Hi, I'm the acmecorp support assistant (Open WebUI). I have access to "
    "internal tools including the order database and the internal wiki. "
    f"[lab] {LAB_NOTICE}"
)


@app.get("/", response_class=HTMLResponse)
async def root() -> str:
    return f"<title>Open WebUI</title><h1>acmecorp support chat</h1><p>{LAB_NOTICE}</p>"


@app.post("/api/chat")
async def chat_reply() -> JSONResponse:
    return JSONResponse({"reply": _CANNED_REPLY}, headers=decoy_headers())
