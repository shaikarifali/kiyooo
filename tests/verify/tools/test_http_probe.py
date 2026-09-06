from __future__ import annotations

import httpx

from kiyooo.verify.safety import ValidatedRequest
from kiyooo.verify.tools.http_probe import parse_response, run


def test_parse_response_captures_status_headers_body() -> None:
    resp = httpx.Response(200, headers={"x-env": "prod"}, text="hello world")
    content = parse_response(resp)
    assert content["status_code"] == 200
    assert content["header"]["x-env"] == "prod"
    assert content["body"] == "hello world"
    assert content["truncated"] is False


def test_parse_response_truncates_oversized_body() -> None:
    resp = httpx.Response(200, text="A" * 20_000)
    content = parse_response(resp)
    assert len(content["body"]) == 16_384
    assert content["truncated"] is True


async def test_run_performs_get_via_injected_client() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert str(request.url) == "https://app.example.com/login"
        return httpx.Response(200, text="Login Page")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    validated = ValidatedRequest(
        tool="http_probe", target="app.example.com", args={"method": "GET", "path": "/login"}
    )
    content = await run(validated, client=client)
    assert content["status_code"] == 200
    assert content["body"] == "Login Page"


async def test_run_performs_head_via_injected_client() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "HEAD"
        return httpx.Response(200)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    validated = ValidatedRequest(
        tool="http_probe", target="app.example.com", args={"method": "HEAD", "path": "/"}
    )
    content = await run(validated, client=client)
    assert content["status_code"] == 200
