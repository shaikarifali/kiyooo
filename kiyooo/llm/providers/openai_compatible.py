"""OpenAI-compatible Chat Completions API — thin `httpx` wrapper, the
bring-your-own-model path (Stage 5's "no feature depends on a
hosted model" principle, extended to "no feature depends on exactly two
named providers"). Real OpenAI (including the Codex/GPT model family),
OpenRouter, vLLM's OpenAI-compatible server, Azure OpenAI's compat mode,
LM Studio, text-generation-webui, and any other server speaking this same
request/response shape all work through this one client — only the
`base_url` (and, where the server checks one, `api_key`) differ.

Structured output via `response_format: {"type": "json_schema", ...}`,
the same "native structured output where available" principle the other
two providers follow — not JSON-mode-and-hope. A server that doesn't
support this mode fails the request with a clear HTTP error rather than
silently returning unstructured text; that's the honest failure mode for
a provider this project has no dedicated test coverage against, not a
quality regression to paper over.
"""

from __future__ import annotations

import json
import time

import httpx

from kiyooo.llm.provider import LlmProvider, LlmResponse, Message, ProviderError

_TIMEOUT_S = 120.0
_SCHEMA_NAME = "kiyooo_verdict"


class OpenAiCompatibleProvider(LlmProvider):
    name = "openai_compatible"

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._client = client or httpx.AsyncClient()

    def _headers(self) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if self._api_key:
            headers["authorization"] = f"Bearer {self._api_key}"
        return headers

    async def complete(
        self,
        messages: list[Message],
        *,
        schema: dict[str, object],
        model: str,
        max_tokens: int = 4096,
        tools: list[dict[str, object]] | None = None,
    ) -> LlmResponse:
        payload: dict[str, object] = {
            "model": model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "max_tokens": max_tokens,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": _SCHEMA_NAME, "schema": schema, "strict": True},
            },
        }

        start = time.monotonic()
        try:
            resp = await self._client.post(
                f"{self._base_url}/chat/completions",
                json=payload,
                headers=self._headers(),
                timeout=_TIMEOUT_S,
            )
        except httpx.HTTPError as exc:
            raise ProviderError(f"{self._base_url} request failed: {exc}") from exc
        latency_ms = int((time.monotonic() - start) * 1000)

        if resp.status_code != 200:
            raise ProviderError(
                f"{self._base_url} returned HTTP {resp.status_code}: {resp.text[:500]}"
            )

        data = resp.json()
        choices = data.get("choices") or []
        if not choices:
            raise ProviderError(f"{self._base_url} response had no choices: {data!r}")
        message = choices[0].get("message", {})
        raw_text = str(message.get("content") or "")
        finish_reason = choices[0].get("finish_reason")
        usage = data.get("usage", {})
        tokens_in = int(usage.get("prompt_tokens", 0))
        tokens_out = int(usage.get("completion_tokens", 0))

        try:
            content = json.loads(raw_text) if raw_text else None
        except json.JSONDecodeError:
            content = None
        if not isinstance(content, dict):
            content = None

        # A content filter or a refusal shows up as an empty/short
        # completion with a non-"stop" finish_reason on most
        # OpenAI-compatible servers — the same "refused, not errored"
        # signal Message/refusal handling expects.
        refused = content is None and finish_reason in {"content_filter", "length", None}

        return LlmResponse(
            content=content,
            raw_text=raw_text,
            model=str(data.get("model", model)),
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=latency_ms,
            refused=refused,
            refusal_reason=raw_text if refused and raw_text else None,
        )

    async def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        try:
            resp = await self._client.post(
                f"{self._base_url}/embeddings",
                json={"model": model, "input": texts},
                headers=self._headers(),
                timeout=_TIMEOUT_S,
            )
        except httpx.HTTPError as exc:
            raise ProviderError(f"{self._base_url} embed request failed: {exc}") from exc

        if resp.status_code != 200:
            raise ProviderError(
                f"{self._base_url} embed returned HTTP {resp.status_code}: {resp.text[:500]}"
            )

        data = resp.json()
        rows = data.get("data")
        if not isinstance(rows, list):
            raise ProviderError(f"{self._base_url} embed response missing 'data': {data!r}")
        return [row["embedding"] for row in rows]
