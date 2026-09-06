"""`kiyooo providers test` / the web UI's "Test connection" button — a
real, minimal, zero-cost reachability check per provider. Never a full
`complete()` call: that would burn real tokens against a hosted provider
just to click a button, which is exactly the "silently spend money"
problem this project treats as a safety issue elsewhere (routing/cost
docs). Ollama's `/api/tags`, Anthropic's `GET /v1/models`, and every
other provider's OpenAI-compatible `GET /v1/models` are all free,
read-only, and prove the same two things a real call would need to
succeed: the endpoint is reachable, and the credential (where one
applies) is accepted. This is the bring-your-own-model path — `provider`
is never checked against a closed list; anything besides "ollama"/
"anthropic" is tested as an OpenAI-compatible endpoint against
`base_url` (required — there's no default to guess for an arbitrary
provider name).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

_TIMEOUT_S = 10.0
_ANTHROPIC_BASE_URL = "https://api.anthropic.com/v1"
_ANTHROPIC_API_VERSION = "2023-06-01"


@dataclass(frozen=True, slots=True)
class ConnectionTestResult:
    ok: bool
    latency_ms: int
    detail: str
    model_found: bool | None = None  # None when the provider gave no model list to check against


async def test_connection(
    *, provider: str, model: str, base_url: str | None, api_key: str | None
) -> ConnectionTestResult:
    if provider == "ollama":
        return await _test_ollama(model, base_url or "http://localhost:11434")
    if provider == "anthropic":
        if not api_key:
            return ConnectionTestResult(
                ok=False, latency_ms=0, detail="no API key configured (ANTHROPIC_API_KEY unset)"
            )
        return await _test_anthropic(model, api_key)
    if not base_url:
        return ConnectionTestResult(
            ok=False,
            latency_ms=0,
            detail=f"provider {provider!r} needs an endpoint_url — there's no default for a "
            "bring-your-own provider",
        )
    return await _test_openai_compatible(model, base_url, api_key)


async def _test_ollama(model: str, base_url: str) -> ConnectionTestResult:
    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
            resp = await client.get(f"{base_url.rstrip('/')}/api/tags")
    except httpx.HTTPError as exc:
        return ConnectionTestResult(
            ok=False,
            latency_ms=int((time.monotonic() - start) * 1000),
            detail=f"{type(exc).__name__}: {exc}",
        )
    latency_ms = int((time.monotonic() - start) * 1000)
    if resp.status_code != 200:
        return ConnectionTestResult(
            ok=False, latency_ms=latency_ms, detail=f"HTTP {resp.status_code} from {base_url}"
        )
    names = [m.get("name") for m in resp.json().get("models", [])]
    model_found = model in names
    detail = (
        f"reachable, {len(names)} model(s) pulled"
        if model_found
        else f"reachable, but {model!r} not in the {len(names)} pulled model(s) — "
        f"'ollama pull {model}' first"
    )
    return ConnectionTestResult(
        ok=True, latency_ms=latency_ms, detail=detail, model_found=model_found
    )


async def _test_openai_compatible(
    model: str, base_url: str, api_key: str | None
) -> ConnectionTestResult:
    """OpenAI, OpenRouter, vLLM, Azure OpenAI-compat, LM Studio, or
    literally any server implementing `GET /v1/models` the same way — the
    bring-your-own-model reachability check.
    """
    start = time.monotonic()
    headers = {"authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
            resp = await client.get(f"{base_url.rstrip('/')}/models", headers=headers)
    except httpx.HTTPError as exc:
        return ConnectionTestResult(
            ok=False,
            latency_ms=int((time.monotonic() - start) * 1000),
            detail=f"{type(exc).__name__}: {exc}",
        )
    latency_ms = int((time.monotonic() - start) * 1000)
    if resp.status_code in (401, 403):
        return ConnectionTestResult(
            ok=False, latency_ms=latency_ms, detail=f"HTTP {resp.status_code} — credential rejected"
        )
    if resp.status_code != 200:
        return ConnectionTestResult(
            ok=False, latency_ms=latency_ms, detail=f"HTTP {resp.status_code} from {base_url}"
        )
    try:
        raw_data = resp.json().get("data")
        if not isinstance(raw_data, list):
            # Some servers (Ollama's own /v1/models compat layer, with no
            # models pulled, is a confirmed real example) return
            # {"data": null} rather than {"data": []} — a valid, reachable
            # response with nothing to list, not a shape to error on.
            raise ValueError("'data' is not a list")
        ids = [m.get("id") for m in raw_data]
    except (ValueError, AttributeError, TypeError):
        # Reachable and authenticated, but the response wasn't the
        # standard {"data": [...]} shape — some proxies/gateways omit or
        # reshape the model list. Still a real, successful connection.
        return ConnectionTestResult(ok=True, latency_ms=latency_ms, detail="reachable")
    model_found = model in ids
    detail = (
        f"reachable, {len(ids)} model(s) listed"
        if model_found
        else f"reachable, but {model!r} not in the {len(ids)} listed model(s)"
    )
    return ConnectionTestResult(
        ok=True, latency_ms=latency_ms, detail=detail, model_found=model_found
    )


async def _test_anthropic(model: str, api_key: str) -> ConnectionTestResult:
    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
            resp = await client.get(
                f"{_ANTHROPIC_BASE_URL}/models",
                headers={"x-api-key": api_key, "anthropic-version": _ANTHROPIC_API_VERSION},
            )
    except httpx.HTTPError as exc:
        return ConnectionTestResult(
            ok=False,
            latency_ms=int((time.monotonic() - start) * 1000),
            detail=f"{type(exc).__name__}: {exc}",
        )
    latency_ms = int((time.monotonic() - start) * 1000)
    if resp.status_code == 401:
        return ConnectionTestResult(
            ok=False, latency_ms=latency_ms, detail="401 — API key rejected"
        )
    if resp.status_code != 200:
        return ConnectionTestResult(
            ok=False, latency_ms=latency_ms, detail=f"HTTP {resp.status_code}"
        )
    ids = [m.get("id") for m in resp.json().get("data", [])]
    model_found = model in ids
    detail = (
        "reachable, API key accepted"
        if model_found
        else f"reachable, API key accepted, but {model!r} not in the account's model list"
    )
    return ConnectionTestResult(
        ok=True, latency_ms=latency_ms, detail=detail, model_found=model_found
    )
