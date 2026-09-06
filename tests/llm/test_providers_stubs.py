from __future__ import annotations

import pytest

from kiyooo.llm.provider import Message
from kiyooo.llm.providers.openai import OpenAiProvider
from kiyooo.llm.providers.openrouter import OpenRouterProvider
from kiyooo.llm.providers.vllm import VllmProvider

_SCHEMA: dict[str, object] = {}


@pytest.mark.parametrize("provider_cls", [OpenAiProvider, VllmProvider, OpenRouterProvider])
async def test_complete_not_implemented(provider_cls: type) -> None:
    provider = provider_cls()
    with pytest.raises(NotImplementedError):
        await provider.complete(
            [Message(role="user", content="hi")], schema=_SCHEMA, model="whatever"
        )


@pytest.mark.parametrize("provider_cls", [OpenAiProvider, VllmProvider, OpenRouterProvider])
async def test_embed_not_implemented(provider_cls: type) -> None:
    provider = provider_cls()
    with pytest.raises(NotImplementedError):
        await provider.embed(["text"], model="whatever")
