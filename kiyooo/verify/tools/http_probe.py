"""Read-only HTTP verification probe: GET/HEAD only, a
capped response body, no auth attempted. `verify/safety.py` has already
rejected anything else (POST/PUT/DELETE, a path not starting with `/`)
before this module ever runs — this trusts its input the way every
boundary-validated function in this codebase does.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from kiyooo.verify.safety import ValidatedRequest

_MAX_BODY_CHARS = 16_384
_TIMEOUT_S = 10.0


def parse_response(resp: httpx.Response) -> dict[str, object]:
    body = resp.text[:_MAX_BODY_CHARS]
    return {
        "status_code": resp.status_code,
        "header": dict(resp.headers),
        "body": body,
        "truncated": len(resp.text) > _MAX_BODY_CHARS,
    }


async def run(
    validated: ValidatedRequest, *, client: httpx.AsyncClient | None = None
) -> dict[str, object]:
    method = str(validated.args["method"])
    path = str(validated.args["path"])
    url = f"https://{validated.target}{path}"

    owns_client = client is None
    http_client = client or httpx.AsyncClient()
    try:
        resp = await http_client.request(method, url, timeout=_TIMEOUT_S, follow_redirects=False)
        return parse_response(resp)
    finally:
        if owns_client:
            await http_client.aclose()
