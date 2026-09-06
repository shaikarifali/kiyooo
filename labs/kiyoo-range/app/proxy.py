"""Same-origin reverse proxy for the `http`/`http_post` categories — this
is what makes kiyoo-range one single place to click through every lab
instead of a link list that sends you off to a different port per
category. `/proxy/{slug}/...` forwards the request to the real decoy
(whatever host:port its `Demo.url` points at, on kiyoo-ai or acmecorp)
server-side and hands the raw response straight back, so the browser
never leaves kiyoo-range's own origin.

Decoy-grade like everything else here: this forwards GET/POST bytes
as-is, it does not add capability the underlying lab doesn't already
have.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

import httpx
from starlette.requests import Request
from starlette.responses import Response

from .catalog import Category

_TIMEOUT_S = 8.0

# Headers that are per-hop, not per-resource — forwarding them (either
# direction) would either be meaningless or actively break the proxied
# response (a stale Content-Length after we've decoded/re-encoded, a
# Host header that would misdirect kiyoo-ai's Host()-routed dispatch).
_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
}


async def proxy(category: Category, subpath: str, request: Request) -> Response:
    demo = category.demo
    if demo.kind not in ("http", "http_post"):
        return Response(
            f"category '{category.slug}' has no HTTP surface to embed "
            f"(demo kind: {demo.kind}) — use the evidence panel instead.",
            status_code=404,
            media_type="text/plain",
        )

    parts = urlsplit(demo.url)
    # demo.url already points at the exact resource this category cares
    # about (e.g. .../.git/config, .../v1/users) — an empty subpath (the
    # common case: the iframe's initial GET, or a same-page JS call to
    # ".") means "that exact resource again." A non-empty subpath (some
    # other in-page relative link) is proxied against the same host.
    target = (
        demo.url
        if not subpath
        else urlunsplit((parts.scheme, parts.netloc, "/" + subpath, parts.query, ""))
    )

    body = await request.body()
    fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP}

    try:
        async with httpx.AsyncClient(
            verify=False,  # noqa: S501 - lab-only self-signed/expired certs are the point
            timeout=_TIMEOUT_S,
            follow_redirects=False,
        ) as client:
            resp = await client.request(
                request.method,
                target,
                content=body or None,
                headers=fwd_headers,
                params=dict(request.query_params),
            )
    except httpx.ConnectError:
        target_lab = demo.needs or "the underlying lab"
        return Response(
            f"connection refused — is {target_lab} running? (kiyoo-labs {demo.needs})".strip(),
            status_code=502,
            media_type="text/plain",
        )
    except httpx.HTTPError as exc:
        return Response(f"proxy error: {exc}", status_code=502, media_type="text/plain")

    out_headers = {k: v for k, v in resp.headers.items() if k.lower() not in _HOP_BY_HOP}
    return Response(content=resp.content, status_code=resp.status_code, headers=out_headers)
