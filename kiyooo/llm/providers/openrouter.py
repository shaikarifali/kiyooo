"""OpenRouter — deferred, not implemented this stage. See
`providers/openai.py`'s docstring: OpenRouter's API is OpenAI-compatible,
differing only in base URL, auth header, and its own `model` string
namespacing (`vendor/model-name`).
"""

from __future__ import annotations

from kiyooo.llm.provider import LlmProvider, LlmResponse, Message


class OpenRouterProvider(LlmProvider):
    name = "openrouter"

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
            "OpenRouter provider is not implemented — see this module's docstring"
        )

    async def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        raise NotImplementedError(
            "OpenRouter provider is not implemented — see this module's docstring"
        )
