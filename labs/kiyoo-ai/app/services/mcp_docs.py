"""`mcp-docs` — the harmless MCP twin.

Byte-identical to `mcp_ops` in every way kiyooo's fingerprinting can see
(protocol, transport, auth-none, TLS config) except the tool catalog. The
harmless catalog is the control case: same exposure, but read-only public
data — the triage step should land this at medium, not critical.
"""

from __future__ import annotations

from typing import Any

from .mcp_common import build_mcp_app

TOOLS: list[dict[str, Any]] = [
    {
        "name": "search_docs",
        "description": "Search public product documentation.",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
    },
    {
        "name": "get_weather",
        "description": "Return current weather for a city.",
        "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}},
    },
    {
        "name": "list_faq",
        "description": "List frequently asked questions.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]

app = build_mcp_app(server_name="mcp-docs (kiyoo-ai lab)", tools=TOOLS)
