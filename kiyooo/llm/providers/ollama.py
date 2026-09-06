"""Ollama — thin `httpx` wrapper over the local `/api/chat` and `/api/embed`
endpoints. The "nothing leaves the host" half of the
hosted-vs-local duality.

Structured output via Ollama's `format` field set to the JSON schema
directly (its native structured-outputs mode, not `format: "json"`'s
looser "valid JSON, no schema enforcement" mode) — the same "native
structured output where available" principle as the Anthropic provider's
forced tool-use.
"""

from __future__ import annotations

import json
import time

import httpx

from kiyooo.llm.provider import LlmProvider, LlmResponse, Message, ProviderError

_DEFAULT_TIMEOUT_S = 120.0  # local inference on CPU can be slow


class OllamaProvider(LlmProvider):
    name = "ollama"

    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        base_url: str = "http://localhost:11434",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = client or httpx.AsyncClient()

    async def complete(
        self,
        messages: list[Message],
        *,
        schema: dict[str, object],
        model: str,
        max_tokens: int = 4096,
        tools: list[dict[str, object]] | None = None,
    ) -> LlmResponse:
        payload = {
            "model": model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "format": schema,
            "stream": False,
            "options": {"num_predict": max_tokens},
        }

        start = time.monotonic()
        try:
            resp = await self._client.post(
                f"{self._base_url}/api/chat", json=payload, timeout=_DEFAULT_TIMEOUT_S
            )
        except httpx.HTTPError as exc:
            raise ProviderError(f"ollama request failed: {exc}") from exc
        latency_ms = int((time.monotonic() - start) * 1000)

        if resp.status_code != 200:
            raise ProviderError(f"ollama returned HTTP {resp.status_code}: {resp.text[:500]}")

        data = resp.json()
        raw_text = str(data.get("message", {}).get("content", ""))
        tokens_in = int(data.get("prompt_eval_count", 0))
        tokens_out = int(data.get("eval_count", 0))

        try:
            content = json.loads(raw_text) if raw_text else None
        except json.JSONDecodeError:
            content = None
        if not isinstance(content, dict):
            content = None

        return LlmResponse(
            content=content,
            raw_text=raw_text,
            model=str(data.get("model", model)),
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=latency_ms,
        )

    async def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        try:
            resp = await self._client.post(
                f"{self._base_url}/api/embed",
                json={"model": model, "input": texts},
                timeout=_DEFAULT_TIMEOUT_S,
            )
        except httpx.HTTPError as exc:
            raise ProviderError(f"ollama embed request failed: {exc}") from exc

        if resp.status_code != 200:
            raise ProviderError(f"ollama embed returned HTTP {resp.status_code}: {resp.text[:500]}")

        data = resp.json()
        embeddings = data.get("embeddings")
        if not isinstance(embeddings, list):
            raise ProviderError(f"ollama embed response missing 'embeddings': {data!r}")
        return embeddings
