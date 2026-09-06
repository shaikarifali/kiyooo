"""`test_connection` — the zero-cost reachability check behind `kiyooo
providers test` / the web UI's "Test connection" button. `httpx.
MockTransport` throughout, same "no live network calls" rule every other
test in this project follows — even though the function under test is
specifically *for* making a real call outside the test suite.
"""

from __future__ import annotations

from unittest.mock import patch

import httpx

from kiyooo.llm.connection_test import test_connection as check_connection


async def test_unknown_provider_without_endpoint_url_fails_cleanly() -> None:
    """No default to fall back to for an arbitrary provider name — this
    must be a clean, actionable failure, never a crash.
    """
    result = await check_connection(
        provider="my-custom-vllm", model="llama3.1:8b", base_url=None, api_key=None
    )
    assert result.ok is False
    assert "endpoint_url" in result.detail


async def test_openai_compatible_handles_null_data_field() -> None:
    """Regression: Ollama's own OpenAI-compat `/v1/models` layer returns
    `{"data": null}` (not `[]`) when no models are pulled — a real,
    reachable response, confirmed live against a running Ollama. This
    must not raise.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"object": "list", "data": None})

    with patch(
        "httpx.AsyncClient", return_value=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ):
        result = await check_connection(
            provider="my-custom-vllm",
            model="llama3.1:8b",
            base_url="http://localhost:11434/v1",
            api_key=None,
        )
    assert result.ok is True
    assert result.model_found is None


async def test_openai_compatible_finds_model_in_list() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"id": "gpt-5-codex"}, {"id": "gpt-5"}]})

    with patch(
        "httpx.AsyncClient", return_value=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ):
        result = await check_connection(
            provider="openai",
            model="gpt-5-codex",
            base_url="https://api.openai.com/v1",
            api_key="sk-test",
        )
    assert result.ok is True
    assert result.model_found is True


async def test_openai_compatible_model_not_in_list() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"id": "gpt-5"}]})

    with patch(
        "httpx.AsyncClient", return_value=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ):
        result = await check_connection(
            provider="openai",
            model="gpt-5-codex",
            base_url="https://api.openai.com/v1",
            api_key="sk-test",
        )
    assert result.ok is True
    assert result.model_found is False


async def test_openai_compatible_401_is_a_clean_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="invalid api key")

    with patch(
        "httpx.AsyncClient", return_value=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ):
        result = await check_connection(
            provider="openai",
            model="gpt-5-codex",
            base_url="https://api.openai.com/v1",
            api_key="bad",
        )
    assert result.ok is False
    assert "credential" in result.detail.lower()


async def test_anthropic_without_api_key_fails_cleanly() -> None:
    result = await check_connection(
        provider="anthropic", model="claude-sonnet-5", base_url=None, api_key=None
    )
    assert result.ok is False
    assert "API key" in result.detail
