from __future__ import annotations

import json

import httpx
import pytest

from kiyooo.llm.provider import Message, ProviderError
from kiyooo.llm.providers.anthropic import AnthropicProvider

_SCHEMA = {"type": "object", "properties": {"verdict": {"type": "string"}}}


def _client(handler: httpx.MockTransport) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=handler)


async def test_complete_parses_tool_use_block() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "claude-sonnet-5",
                "content": [
                    {
                        "type": "tool_use",
                        "name": "emit_structured_output",
                        "input": {"verdict": "true_positive", "confidence": 0.9},
                    }
                ],
                "usage": {"input_tokens": 120, "output_tokens": 40},
            },
        )

    provider = AnthropicProvider("test-key", client=_client(httpx.MockTransport(handler)))
    response = await provider.complete(
        [Message(role="system", content="sys"), Message(role="user", content="hi")],
        schema=_SCHEMA,
        model="claude-sonnet-5",
    )
    assert response.content == {"verdict": "true_positive", "confidence": 0.9}
    assert response.tokens_in == 120
    assert response.tokens_out == 40
    assert response.refused is False


async def test_complete_no_tool_use_is_refusal() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "claude-sonnet-5",
                "content": [{"type": "text", "text": "I can't help assess this."}],
                "usage": {"input_tokens": 50, "output_tokens": 10},
            },
        )

    provider = AnthropicProvider("test-key", client=_client(httpx.MockTransport(handler)))
    response = await provider.complete(
        [Message(role="user", content="hi")], schema=_SCHEMA, model="claude-sonnet-5"
    )
    assert response.refused is True
    assert response.content is None
    assert "can't help" in (response.refusal_reason or "")


async def test_complete_http_error_raises_provider_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="rate limited")

    provider = AnthropicProvider("test-key", client=_client(httpx.MockTransport(handler)))
    with pytest.raises(ProviderError):
        await provider.complete(
            [Message(role="user", content="hi")], schema=_SCHEMA, model="claude-sonnet-5"
        )


async def test_system_role_extracted_into_top_level_system_field() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "model": "claude-sonnet-5",
                "content": [{"type": "tool_use", "name": "emit_structured_output", "input": {}}],
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        )

    provider = AnthropicProvider("test-key", client=_client(httpx.MockTransport(handler)))
    await provider.complete(
        [Message(role="system", content="be careful"), Message(role="user", content="hi")],
        schema=_SCHEMA,
        model="claude-sonnet-5",
    )
    assert captured["system"] == "be careful"
    assert all(m["role"] != "system" for m in captured["messages"])  # type: ignore[union-attr]


async def test_embed_not_implemented() -> None:
    provider = AnthropicProvider("test-key")
    with pytest.raises(NotImplementedError):
        await provider.embed(["text"], model="whatever")
