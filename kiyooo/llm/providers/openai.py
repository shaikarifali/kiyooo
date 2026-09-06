"""OpenAI — deferred, not implemented this stage.

Stage 5 names 5 providers; Anthropic and Ollama were built and
tested for real (see `providers/anthropic.py`, `providers/ollama.py`) —
between them they cover the two poles the rest of this project's design
actually cares about (hosted frontier vs. local, the design's "Hosted vs.
local" table). OpenAI, vLLM, and OpenRouter are all OpenAI-Chat-Completions-
API-shaped (`POST /chat/completions` with `response_format: {"type":
"json_schema", "json_schema": {...}}` for structured output, an
OpenAI-compatible `/embeddings` endpoint) — the same shape this module
would implement, differing only in base URL and auth header. Building one
without a way to genuinely test it against that shape in this sandbox
(same reasoning as Stage 3's GCP/Azure stubs) would ship code nobody has
verified; this defines the interface so a real implementation has a clear
home, not a silent gap.
"""

from __future__ import annotations

from kiyooo.llm.provider import LlmProvider, LlmResponse, Message


class OpenAiProvider(LlmProvider):
    name = "openai"

    async def complete(
        self,
        messages: list[Message],
        *,
        schema: dict[str, object],
        model: str,
        max_tokens: int = 4096,
        tools: list[dict[str, object]] | None = None,
    ) -> LlmResponse:
        raise NotImplementedError(
            "OpenAI provider is not implemented — see this module's docstring"
        )

    async def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        raise NotImplementedError(
            "OpenAI provider is not implemented — see this module's docstring"
        )
