"""Factory for the three MCP twin/poisoned servers.

Protocol-accurate on purpose: `initialize` and `tools/list` follow the real
MCP JSON-RPC 2.0 shape, because a decoy that only *looks* right doesn't
test anything — kiyooo's `exposed-mcp-server` category matches on real
JSON-RPC 2.0 response bodies and the `mcp-protocol-version` header, so
this responds exactly the way a real server would to those two methods.

`tools/call` — and every other method — is never implemented. It returns
405 with a lab notice instead of a JSON-RPC error, so it's unambiguous to
a human *and* impossible to mistake for a working tool invocation. See
this is the one architectural rule the whole lab follows.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

from ..common import LAB_NOTICE, decoy_headers

PROTOCOL_VERSION = "2025-06-18"


def handle_rpc(body: dict[str, Any], *, server_name: str, tools: list[dict[str, Any]]) -> Response:
    """The JSON-RPC 2.0 dispatch shared by every MCP twin — factored out
    so the drift scenario (`internal_tools.py`) can serve the exact same
    `mcp-ops` responses once "enabled", instead of re-implementing them.
    """
    method = body.get("method")
    rpc_id = body.get("id")
    headers = decoy_headers({"mcp-protocol-version": PROTOCOL_VERSION})

    if method == "initialize":
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": server_name, "version": "lab-1.0.0"},
                    "instructions": LAB_NOTICE,
                },
            },
            headers=headers,
        )

    if method == "tools/list":
        return JSONResponse(
            {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": tools}}, headers=headers
        )

    # tools/call and everything else: decoy-grade, not exploit-grade.
    return JSONResponse(
        {"lab_notice": "decoy - tools/call not implemented", "requested_method": method},
        status_code=405,
        headers=headers,
    )


def try_it_widget() -> str:
    """Three buttons that POST a real JSON-RPC request from the browser
    and render the raw response — MCP is JSON-RPC-over-POST, so there's
    no plain link to click to see the tool catalog otherwise. Vanilla JS,
    no dependencies, on purpose (this needs to stay a self-contained lab
    page, not pull in a CDN script).
    """
    return """
<div style="font-family: monospace">
  <button onclick="mcpCall('initialize')">initialize</button>
  <button onclick="mcpCall('tools/list')">tools/list</button>
  <button onclick="mcpCall('tools/call')">tools/call (watch this fail)</button>
  <pre id="mcp-out" style="background:#f4f4f4; padding:1em; white-space:pre-wrap;"></pre>
</div>
<script>
async function mcpCall(method) {
  const out = document.getElementById('mcp-out');
  out.textContent = 'requesting ' + method + ' ...';
  const res = await fetch('.', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({jsonrpc: '2.0', id: 1, method: method, params: {}}),
  });
  const body = await res.text();
  out.textContent = 'HTTP ' + res.status + '\\n\\n' + JSON.stringify(JSON.parse(body), null, 2);
}
</script>
"""


def build_mcp_app(*, server_name: str, tools: list[dict[str, Any]]) -> FastAPI:
    app = FastAPI(title=server_name, docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    async def landing() -> str:
        tool_names = ", ".join(t["name"] for t in tools)
        return (
            f"<h1>{server_name}</h1>"
            f"<p>{LAB_NOTICE}</p>"
            f"<p>MCP server (JSON-RPC 2.0 over HTTP POST /). "
            f"Tools advertised: {tool_names}.</p>"
            f"<p>Click a button to send the real JSON-RPC request — "
            f"a browser can't do this with a plain link, POST isn't "
            f"clickable. <code>tools/call</code> is not implemented.</p>"
            f"{try_it_widget()}"
        )

    @app.post("/")
    async def rpc(request: Request) -> Response:
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}},
                status_code=400,
                headers=decoy_headers({"mcp-protocol-version": PROTOCOL_VERSION}),
            )
        return handle_rpc(body, server_name=server_name, tools=tools)

    return app
