from __future__ import annotations

import json

import httpx
import pytest

from kiyooo.llm.provider import Message, ProviderError
from kiyooo.llm.providers.openai_compatible import OpenAiCompatibleProvider

_SCHEMA = {"type": "object", "properties": {"verdict": {"type": "string"}}}
_BASE_URL = "https://example.test/v1"


def _client(handler: httpx.MockTransport) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=handler)


async def test_complete_parses_json_content_and_sends_auth_header() -> None:
    seen_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(request.headers)
        return httpx.Response(
            200,
            json={
                "model": "gpt-5-codex",
                "choices": [
                    {
                        "message": {
                            "content": json.dumps({"verdict": "true_positive", "confidence": 0.9})
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 120, "completion_tokens": 40},
            },
        )

    provider = OpenAiCompatibleProvider(
        base_url=_BASE_URL, api_key="sk-test", client=_client(httpx.MockTransport(handler))
    )
    response = await provider.complete(
        [Message(role="system", content="sys"), Message(role="user", content="hi")],
        schema=_SCHEMA,
        model="gpt-5-codex",
    )
    assert response.content == {"verdict": "true_positive", "confidence": 0.9}
    assert response.tokens_in == 120
    assert response.tokens_out == 40
    assert response.refused is False
    assert seen_headers["authorization"] == "Bearer sk-test"


async def test_complete_with_no_api_key_omits_auth_header() -> None:
    seen_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(request.headers)
        return httpx.Response(
            200,
            json={
                "model": "local-model",
                "choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}],
                "usage": {},
            },
        )

    provider = OpenAiCompatibleProvider(
        base_url=_BASE_URL, api_key=None, client=_client(httpx.MockTransport(handler))
    )
    await provider.complete(
        [Message(role="user", content="hi")], schema=_SCHEMA, model="local-model"
    )
    assert "authorization" not in seen_headers


async def test_complete_content_filter_finish_reason_is_a_refusal() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "gpt-5-codex",
                "choices": [
                    {
                        "message": {"content": "I can't help with that"},
                        "finish_reason": "content_filter",
                    }
                ],
                "usage": {},
            },
        )

    provider = OpenAiCompatibleProvider(
        base_url=_BASE_URL, api_key="sk-test", client=_client(httpx.MockTransport(handler))
    )
    response = await provider.complete(
        [Message(role="user", content="hi")], schema=_SCHEMA, model="gpt-5-codex"
    )
    assert response.content is None
    assert response.refused is True
    assert response.refusal_reason == "I can't help with that"


async def test_complete_http_error_raises_provider_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="invalid api key")

    provider = OpenAiCompatibleProvider(
        base_url=_BASE_URL, api_key="bad-key", client=_client(httpx.MockTransport(handler))
    )
    with pytest.raises(ProviderError, match="401"):
        await provider.complete(
            [Message(role="user", content="hi")], schema=_SCHEMA, model="gpt-5-codex"
        )


async def test_embed_returns_vectors() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {"embedding": [0.1, 0.2], "index": 0},
                    {"embedding": [0.3, 0.4], "index": 1},
                ]
            },
        )

    provider = OpenAiCompatibleProvider(
        base_url=_BASE_URL, api_key="sk-test", client=_client(httpx.MockTransport(handler))
    )
    vectors = await provider.embed(["a", "b"], model="text-embedding-3-small")
    assert vectors == [[0.1, 0.2], [0.3, 0.4]]
