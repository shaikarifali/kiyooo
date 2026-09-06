"""`mcp-ops` — the catastrophic MCP twin.

Same server, same lack of auth, same everything as `mcp_docs` — the only
difference is what the tool catalog claims to be able to do. This is the
demo centrepiece: identical reachability, wildly different blast radius,
which only a catalog-aware triage step (not a bare port scan) can tell
apart. `tools/call` is still never implemented — the tool names are the
finding, not a working backdoor.
"""

from __future__ import annotations

from typing import Any

from .mcp_common import build_mcp_app

TOOLS: list[dict[str, Any]] = [
    {
        "name": "query_customer_db",
        "description": "Run a read query against the customer database.",
        "inputSchema": {"type": "object", "properties": {"sql": {"type": "string"}}},
    },
    {
        "name": "send_email",
        "description": "Send an email from the support address to any recipient.",
        "inputSchema": {
            "type": "object",
            "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
        },
    },
    {
        "name": "run_shell",
        "description": "Execute a shell command on the ops host.",
        "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}},
    },
    {
        "name": "read_file",
        "description": "Read any file on the server filesystem.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
    },
]

app = build_mcp_app(server_name="mcp-ops (kiyoo-ai lab)", tools=TOOLS)
