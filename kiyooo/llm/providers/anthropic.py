"""Anthropic Messages API — thin `httpx` wrapper.

Structured output via forced tool-use: `schema` becomes the single tool's
`input_schema`, and `tool_choice` forces the model to call it. A response
with no matching `tool_use` block is treated as a refusal —
Anthropic has no explicit refusal flag, so "declined to call the tool" is
the closest observable signal.
"""

from __future__ import annotations

import time

import httpx

from kiyooo.llm.provider import LlmProvider, LlmResponse, Message, ProviderError

_API_VERSION = "2023-06-01"
_DEFAULT_BASE_URL = "https://api.anthropic.com/v1"
_TOOL_NAME = "emit_structured_output"
_TIMEOUT_S = 60.0


class AnthropicProvider(LlmProvider):
    name = "anthropic"

    def __init__(
        self,
        api_key: str,
        *,
        client: httpx.AsyncClient | None = None,
        base_url: str = _DEFAULT_BASE_URL,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url
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
        # Anthropic has no "system" role in `messages[]` — it's a separate
        # top-level field. Evidence never enters it; it's
        # only ever the static, versioned prompt text a `Message(role=
        # "system", ...)` carries.
        system_text = "\n\n".join(m.content for m in messages if m.role == "system")
        conversation = [
            {"role": m.role, "content": m.content} for m in messages if m.role != "system"
        ]

        payload: dict[str, object] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": conversation,
            "tools": [
                {
                    "name": _TOOL_NAME,
                    "description": "Emit the structured verdict matching the required schema.",
                    "input_schema": schema,
                }
            ],
            "tool_choice": {"type": "tool", "name": _TOOL_NAME},
        }
        if system_text:
            payload["system"] = system_text

        start = time.monotonic()
        try:
            resp = await self._client.post(
                f"{self._base_url}/messages",
                json=payload,
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": _API_VERSION,
                    "content-type": "application/json",
                },
                timeout=_TIMEOUT_S,
            )
        except httpx.HTTPError as exc:
            raise ProviderError(f"anthropic request failed: {exc}") from exc
        latency_ms = int((time.monotonic() - start) * 1000)

        if resp.status_code != 200:
            raise ProviderError(f"anthropic returned HTTP {resp.status_code}: {resp.text[:500]}")

        data = resp.json()
        usage = data.get("usage", {})
        tokens_in = int(usage.get("input_tokens", 0))
        tokens_out = int(usage.get("output_tokens", 0))

        tool_input: dict[str, object] | None = None
        text_parts: list[str] = []
        for block in data.get("content", []):
            if block.get("type") == "tool_use" and block.get("name") == _TOOL_NAME:
                tool_input = block.get("input")
            elif block.get("type") == "text":
                text_parts.append(str(block.get("text", "")))
        raw_text = "\n".join(text_parts)

        if tool_input is None:
            return LlmResponse(
                content=None,
                raw_text=raw_text,
                model=str(data.get("model", model)),
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                latency_ms=latency_ms,
                refused=True,
                refusal_reason=raw_text or "model returned no structured tool call",
            )

        return LlmResponse(
            content=tool_input,
            raw_text=raw_text,
            model=str(data.get("model", model)),
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=latency_ms,
        )

    async def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        raise NotImplementedError(
            "Anthropic has no embeddings API — configure embedding_provider "
            "to ollama (nomic-embed-text) or another embedding-capable "
            "provider for triage/memory.py."
        )
