"""`ai-portal` — a shadow AI SaaS tenant decoy.

The real deployment CNAMEs this hostname to an actual third-party AI SaaS
login (a genuinely unsanctioned tenant is the finding). Locally/offline
there's nothing to CNAME to, so this stands in with the same signature
kiyooo's `shadow-ai-saas-tenant` category looks for: a `Server` header
naming the platform, plus body text matching a hosted-AI-platform phrase.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from ..common import LAB_NOTICE, decoy_headers

app = FastAPI(title="ai-portal (kiyoo-ai lab, shadow SaaS-shaped)", docs_url=None, redoc_url=None)


@app.get("/", response_class=HTMLResponse)
async def root() -> HTMLResponse:
    return HTMLResponse(
        f"<h1>acmecorp-support-bot</h1><p>Built with Streamlit.</p><p>{LAB_NOTICE}</p>",
        headers=decoy_headers({"server": "Streamlit"}),
    )
