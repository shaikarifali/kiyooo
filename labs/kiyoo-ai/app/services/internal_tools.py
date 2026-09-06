"""`internal-tools` — the drift scenario.

Before: nginx-allowlist-shaped 403, no MCP protocol advertised at all.
After `scenarios/dev-exposes-prod.sh` runs: the exact same dangerous
catalog as `mcp-ops` (query_customer_db, send_email, run_shell, read_file)
appears, live, with no server restart — a re-scan should produce an
`ASSET_NEW` + `AUTH_REMOVED` change event straight into critical triage.

State is a marker file, not an env var, on purpose: the toggle scripts run
against an already-started container and can't change its environment —
they can only touch the filesystem (or hit an admin endpoint, which would
itself be a second attack surface this lab doesn't need).
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

from ..common import LAB_NOTICE, decoy_headers
from .mcp_common import PROTOCOL_VERSION, handle_rpc, try_it_widget
from .mcp_ops import TOOLS as DANGEROUS_TOOLS

_DEFAULT_STATE_FILE = "/tmp/kiyoo-ai-drift-enabled"  # noqa: S108 - lab-only marker file, not a secret


def _drift_enabled() -> bool:
    state_file = os.environ.get("KIYOO_AI_DRIFT_STATE_FILE", _DEFAULT_STATE_FILE)
    return Path(state_file).exists()


app = FastAPI(title="internal-tools (kiyoo-ai lab, drift scenario)", docs_url=None, redoc_url=None)


@app.get("/", response_class=HTMLResponse)
async def landing() -> Response:
    if not _drift_enabled():
        return HTMLResponse(
            f"<h1>403 Forbidden</h1><p>Blocked by allowlist.</p><p>{LAB_NOTICE}</p>"
            f"<p>Run <code>scenarios/dev-exposes-prod.sh</code>, then reload — "
            f"or click below to see the block itself.</p>{try_it_widget()}",
            status_code=403,
            headers=decoy_headers(),
        )
    tool_names = ", ".join(t["name"] for t in DANGEROUS_TOOLS)
    return HTMLResponse(
        f"<h1>internal-tools</h1><p>{LAB_NOTICE}</p>"
        f"<p>MCP server (JSON-RPC 2.0 over HTTP POST /). Tools advertised: {tool_names}.</p>"
        f"{try_it_widget()}"
    )


@app.post("/")
async def rpc(request: Request) -> Response:
    if not _drift_enabled():
        return JSONResponse(
            {"lab_notice": "blocked by allowlist"},
            status_code=403,
            headers=decoy_headers({"mcp-protocol-version": PROTOCOL_VERSION}),
        )
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}},
            status_code=400,
            headers=decoy_headers({"mcp-protocol-version": PROTOCOL_VERSION}),
        )
    return handle_rpc(body, server_name="internal-tools (kiyoo-ai lab)", tools=DANGEROUS_TOOLS)
