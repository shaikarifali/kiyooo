"""vLLM — deferred, not implemented this stage. See `providers/openai.py`'s
docstring: vLLM's OpenAI-compatible server exposes the same
`/chat/completions` + `response_format` shape, differing only in that it's
typically self-hosted with no auth header at all.
"""

from __future__ import annotations

from kiyooo.llm.provider import LlmProvider, LlmResponse, Message


class VllmProvider(LlmProvider):
    name = "vllm"

    async def complete(
        self,
        messages: list[Message],
        *,
        schema: dict[str, object],
        model: str,
        max_tokens: int = 4096,
        tools: list[dict[str, object]] | None = None,
    ) -> LlmResponse:
        raise NotImplementedError("vLLM provider is not implemented — see this module's docstring")

    async def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        raise NotImplementedError("vLLM provider is not implemented — see this module's docstring")
