"""Generic, config-driven REST/JSON connector (Stage 1b, "or
any other" tool). Every other adapter in this package is one hardwired
`parse_*()` per vendor because Mandiant/Tenable's shapes were verified
against real docs; this one instead validates a `GenericRestConfig` (the
org supplies base URL, auth, and a dotted-path field mapping) so a new
ASM/VM tool doesn't need a code change or a redeploy to onboard — the
same "map columns, don't write a parser" idea `importers/csv_generic.py`
already uses for files, generalized to a live REST/JSON API.

`credential_ref` is the only thing that ever touches a secret — never a
raw key in `config` (invariant #6/#7); resolved the same way, and by the
same function, as a bring-your-own LLM provider's credential.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field, model_validator

from kiyooo.db.models import AssetType
from kiyooo.ingest.base import ImportedFinding

if TYPE_CHECKING:
    import httpx

_AuthType = Literal["none", "bearer", "header", "basic"]


class FieldMapping(BaseModel):
    """Dotted paths into one vendor item's JSON object, e.g. `"plugin.id"`
    for a nested field or `"id"` for a flat one. No array indexing — a
    single item's fields are addressed relative to that item, after
    `GenericRestConfig.items_path` has already pulled the list out of the
    envelope.
    """

    external_id: str
    vendor_issue_type: str
    title: str
    vendor_severity: str
    asset_value: str


class GenericRestConfig(BaseModel):
    base_url: str
    path: str
    method: Literal["GET", "POST"] = "GET"
    auth_type: _AuthType = "none"
    auth_header: str | None = None
    auth_value_template: str | None = None
    basic_username: str | None = None
    credential_ref: str | None = None
    request_body: dict[str, object] | None = None
    items_path: str = ""
    field_mapping: FieldMapping
    default_asset_type: AssetType
    since_param: str | None = None
    next_cursor_path: str | None = None
    cursor_param: str | None = None
    max_pages: int = Field(default=20, ge=1, le=200)

    @model_validator(mode="after")
    def _check_auth_fields(self) -> GenericRestConfig:
        if self.auth_type in ("bearer", "header", "basic") and not self.credential_ref:
            raise ValueError(f"auth_type={self.auth_type!r} needs credential_ref")
        if self.auth_type == "header" and not (self.auth_header and self.auth_value_template):
            raise ValueError("auth_type='header' needs auth_header and auth_value_template")
        if self.auth_type == "basic" and not self.basic_username:
            raise ValueError("auth_type='basic' needs basic_username")
        return self


def _get_path(obj: object, path: str) -> object | None:
    if not path:
        return obj
    current = obj
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def parse_item(raw: dict[str, object], config: GenericRestConfig) -> ImportedFinding:
    mapping = config.field_mapping
    external_id = _get_path(raw, mapping.external_id)
    if external_id is None:
        raise ValueError(f"item has no value at external_id path {mapping.external_id!r}")
    asset_value = _get_path(raw, mapping.asset_value)
    if asset_value is None:
        raise ValueError(f"item has no value at asset_value path {mapping.asset_value!r}")
    vendor_issue_type = _get_path(raw, mapping.vendor_issue_type)
    title = _get_path(raw, mapping.title)
    vendor_severity = _get_path(raw, mapping.vendor_severity)
    return ImportedFinding(
        external_id=str(external_id),
        vendor_issue_type=str(vendor_issue_type) if vendor_issue_type is not None else "unknown",
        title=str(title) if title is not None else str(vendor_issue_type or "untitled"),
        vendor_severity=str(vendor_severity) if vendor_severity is not None else "unknown",
        asset_type=config.default_asset_type,
        asset_value=str(asset_value),
        evidence_content=raw,
        raw_payload=raw,
    )


def _build_auth_headers(config: GenericRestConfig, credential: str | None) -> dict[str, str]:
    if config.auth_type == "none":
        return {}
    if credential is None:
        raise ValueError(
            f"auth_type={config.auth_type!r} needs a credential — check credential_ref"
        )
    if config.auth_type == "bearer":
        return {"Authorization": f"Bearer {credential}"}
    if config.auth_type == "header":
        assert config.auth_header is not None
        assert config.auth_value_template is not None
        return {config.auth_header: config.auth_value_template.format(credential=credential)}
    assert config.auth_type == "basic"
    assert config.basic_username is not None
    token = base64.b64encode(f"{config.basic_username}:{credential}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


async def fetch_items(
    client: httpx.AsyncClient,
    config: GenericRestConfig,
    *,
    credential: str | None,
    since: str | None = None,
) -> list[dict[str, object]]:
    """Fetches every page (cursor-based, capped at `max_pages` — a
    misconfigured or infinitely-looping cursor must not hang a sync
    forever) and returns the flattened list of raw vendor items, each
    still in its original JSON shape for `parse_item`/redaction/
    injection-scanning downstream.
    """
    headers = _build_auth_headers(config, credential)
    url = f"{config.base_url.rstrip('/')}/{config.path.lstrip('/')}"
    items: list[dict[str, object]] = []
    cursor: str | None = None
    for _ in range(config.max_pages):
        params: dict[str, str] = {}
        if since and config.since_param:
            params[config.since_param] = since
        if cursor and config.cursor_param:
            params[config.cursor_param] = cursor
        resp = await client.request(
            config.method,
            url,
            headers=headers,
            params=params or None,
            json=config.request_body,
            timeout=30.0,
        )
        resp.raise_for_status()
        body = resp.json()
        page_items = _get_path(body, config.items_path)
        if page_items is None:
            page_items = body if isinstance(body, list) else []
        if not isinstance(page_items, list):
            raise ValueError(f"items_path={config.items_path!r} did not resolve to a list")
        items.extend(item for item in page_items if isinstance(item, dict))

        if not config.next_cursor_path or not config.cursor_param or not page_items:
            break
        next_cursor = _get_path(body, config.next_cursor_path)
        if not next_cursor:
            break
        cursor = str(next_cursor)
    return items
