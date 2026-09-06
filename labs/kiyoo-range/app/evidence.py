"""Fetches live evidence for one category's `Demo` — this is what makes
the app an actual vulnerable-machine walkthrough instead of a link list:
clicking "fetch evidence" in the browser hits kiyoo-range's own backend
(same-origin, no CORS wall), and this module does the real network call
server-side and hands back the raw response to render.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

from .catalog import Category, Demo
from .decoys import DECOYS

_TIMEOUT_S = 5.0


@dataclass(frozen=True, slots=True)
class EvidenceResult:
    ok: bool
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: str = ""
    # True when `body` is a captured example shown because the live fetch
    # couldn't reach `demo.needs` — never set on a real, live response.
    offline: bool = False


async def fetch(category: Category) -> EvidenceResult:
    demo = category.demo
    try:
        if demo.kind == "http":
            async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT_S) as client:  # noqa: S501 - lab-only self-signed certs are the point
                resp = await client.get(demo.url)
                return EvidenceResult(True, resp.status_code, dict(resp.headers), resp.text)

        if demo.kind == "http_post":
            async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT_S) as client:  # noqa: S501
                resp = await client.post(demo.url, json=demo.json_body)
                return EvidenceResult(True, resp.status_code, dict(resp.headers), resp.text)

        if demo.kind == "tcp":
            return await _fetch_tcp(demo)

        if demo.kind == "local":
            fn = DECOYS[demo.local_slug]
            status, headers, body = fn()
            return EvidenceResult(True, status, headers, body)

        return EvidenceResult(False, error=f"unknown demo kind: {demo.kind}")

    except httpx.ConnectError:
        target = demo.needs or "the service"
        return _offline_fallback(demo, f"connection refused — is {target} running?")
    except httpx.TimeoutException:
        return _offline_fallback(demo, f"timed out after {_TIMEOUT_S:.0f}s")
    except Exception as exc:  # noqa: BLE001 - surface any failure as evidence text, not a 500
        return _offline_fallback(demo, f"{type(exc).__name__}: {exc}")


def _offline_fallback(demo: Demo, reason: str) -> EvidenceResult:
    """A live fetch just failed — if this category ships a captured
    example of what `needs` would have returned, show that (clearly
    labeled `offline=True`) instead of a bare error. Keeps a reviewer who
    hasn't started labs/kiyoo-ai or labs/acmecorp from seeing 19 of 23
    cards go dark.
    """
    if not demo.offline_example:
        return EvidenceResult(False, error=reason)
    return EvidenceResult(True, body=demo.offline_example, offline=True)


async def _fetch_tcp(demo: Demo) -> EvidenceResult:
    host, port = demo.tcp_host, demo.tcp_port
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=_TIMEOUT_S
        )
    except (TimeoutError, OSError) as exc:
        return _offline_fallback(demo, f"connect to {host}:{port} failed: {exc}")

    try:
        raw = await asyncio.wait_for(reader.read(demo.tcp_read_bytes), timeout=_TIMEOUT_S)
    finally:
        writer.close()

    printable = raw.decode("latin-1", errors="replace")
    hexdump = raw.hex(" ", 2)
    body = f"{len(raw)} bytes read from {host}:{port}\n\nhex:\n{hexdump}\n\nlatin-1:\n{printable}"
    return EvidenceResult(True, status=None, body=body)
