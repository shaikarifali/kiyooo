from __future__ import annotations

import json

import httpx
import pytest

from kiyooo.llm.provider import Message, ProviderError
from kiyooo.llm.providers.ollama import OllamaProvider

_SCHEMA = {"type": "object", "properties": {"verdict": {"type": "string"}}}


def _client(handler: httpx.MockTransport) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=handler)


async def test_complete_parses_json_content() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "llama3.1:8b",
                "message": {
                    "role": "assistant",
                    "content": json.dumps({"verdict": "false_positive", "confidence": 0.6}),
                },
                "prompt_eval_count": 200,
                "eval_count": 30,
            },
        )

    provider = OllamaProvider(client=_client(httpx.MockTransport(handler)))
    response = await provider.complete(
        [Message(role="system", content="sys"), Message(role="user", content="hi")],
        schema=_SCHEMA,
        model="llama3.1:8b",
    )
    assert response.content == {"verdict": "false_positive", "confidence": 0.6}
    assert response.tokens_in == 200
    assert response.tokens_out == 30


async def test_complete_non_json_content_returns_none() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "llama3.1:8b",
                "message": {"role": "assistant", "content": "not json at all"},
                "prompt_eval_count": 10,
                "eval_count": 5,
            },
        )

    provider = OllamaProvider(client=_client(httpx.MockTransport(handler)))
    response = await provider.complete(
        [Message(role="user", content="hi")], schema=_SCHEMA, model="llama3.1:8b"
    )
    assert response.content is None
    assert response.refused is False


async def test_complete_http_error_raises_provider_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="server error")

    provider = OllamaProvider(client=_client(httpx.MockTransport(handler)))
    with pytest.raises(ProviderError):
        await provider.complete(
            [Message(role="user", content="hi")], schema=_SCHEMA, model="llama3.1:8b"
        )


async def test_embed_returns_vectors() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"model": "nomic-embed-text", "embeddings": [[0.1, 0.2], [0.3, 0.4]]}
        )

    provider = OllamaProvider(client=_client(httpx.MockTransport(handler)))
    vectors = await provider.embed(["a", "b"], model="nomic-embed-text")
    assert vectors == [[0.1, 0.2], [0.3, 0.4]]


async def test_embed_missing_embeddings_key_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"model": "nomic-embed-text"})

    provider = OllamaProvider(client=_client(httpx.MockTransport(handler)))
    with pytest.raises(ProviderError):
        await provider.embed(["a"], model="nomic-embed-text")
