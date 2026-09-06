from __future__ import annotations

import httpx
import pytest

from kiyooo.db.models import AssetType
from kiyooo.ingest.adapters.generic_rest import (
    FieldMapping,
    GenericRestConfig,
    fetch_items,
    parse_item,
)

_BASE = dict(
    base_url="https://asm-tool.example.com",
    path="/api/v1/issues",
    field_mapping=FieldMapping(
        external_id="id",
        vendor_issue_type="issueType",
        title="title",
        vendor_severity="severity",
        asset_value="asset.hostname",
    ),
    default_asset_type=AssetType.SUBDOMAIN,
)


def test_parse_item_nested_field_mapping() -> None:
    imported = parse_item(
        {
            "id": "abc-1",
            "issueType": "expired_cert",
            "title": "Expired TLS certificate",
            "severity": "high",
            "asset": {"hostname": "app.example.com"},
        },
        GenericRestConfig(**_BASE),
    )
    assert imported.external_id == "abc-1"
    assert imported.vendor_issue_type == "expired_cert"
    assert imported.asset_type == AssetType.SUBDOMAIN
    assert imported.asset_value == "app.example.com"
    assert imported.vendor_severity == "high"


def test_parse_item_missing_asset_value_raises() -> None:
    with pytest.raises(ValueError, match="asset_value"):
        parse_item({"id": "abc-1", "asset": {}}, GenericRestConfig(**_BASE))


def test_parse_item_missing_optional_fields_default_to_unknown() -> None:
    imported = parse_item(
        {"id": "abc-1", "asset": {"hostname": "app.example.com"}}, GenericRestConfig(**_BASE)
    )
    assert imported.vendor_issue_type == "unknown"
    assert imported.vendor_severity == "unknown"
    assert imported.title == "untitled"


def test_config_rejects_bearer_auth_without_credential_ref() -> None:
    with pytest.raises(ValueError, match="credential_ref"):
        GenericRestConfig(**_BASE, auth_type="bearer")


def test_config_rejects_header_auth_without_header_fields() -> None:
    with pytest.raises(ValueError, match="auth_header"):
        GenericRestConfig(**_BASE, auth_type="header", credential_ref="env:X")


def test_config_rejects_basic_auth_without_username() -> None:
    with pytest.raises(ValueError, match="basic_username"):
        GenericRestConfig(**_BASE, auth_type="basic", credential_ref="env:X")


async def test_fetch_items_sends_bearer_auth_header() -> None:
    seen_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(request.headers)
        return httpx.Response(200, json={"data": {"issues": [{"id": "1"}, {"id": "2"}]}})

    config = GenericRestConfig(
        **_BASE, items_path="data.issues", auth_type="bearer", credential_ref="env:X"
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        items = await fetch_items(client, config, credential="secret-token")

    assert seen_headers["authorization"] == "Bearer secret-token"
    assert len(items) == 2


async def test_fetch_items_root_array_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"id": "1"}, {"id": "2"}, {"id": "3"}])

    config = GenericRestConfig(**_BASE)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        items = await fetch_items(client, config, credential=None)

    assert len(items) == 3


async def test_fetch_items_paginates_via_cursor_and_stops_when_none_returned() -> None:
    pages = [
        {"issues": [{"id": "1"}, {"id": "2"}], "next": "page-2"},
        {"issues": [{"id": "3"}], "next": None},
    ]
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        body = pages[call_count]
        call_count += 1
        return httpx.Response(200, json=body)

    config = GenericRestConfig(
        **_BASE, items_path="issues", next_cursor_path="next", cursor_param="cursor"
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        items = await fetch_items(client, config, credential=None)

    assert call_count == 2
    assert [i["id"] for i in items] == ["1", "2", "3"]


async def test_fetch_items_pagination_capped_at_max_pages() -> None:
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(
            200, json={"issues": [{"id": str(call_count)}], "next": f"page-{call_count + 1}"}
        )

    config = GenericRestConfig(
        **_BASE,
        items_path="issues",
        next_cursor_path="next",
        cursor_param="cursor",
        max_pages=3,
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        items = await fetch_items(client, config, credential=None)

    assert call_count == 3
    assert len(items) == 3


async def test_fetch_items_http_error_propagates() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="unauthorized")

    config = GenericRestConfig(**_BASE, auth_type="bearer", credential_ref="env:X")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await fetch_items(client, config, credential="bad-token")
