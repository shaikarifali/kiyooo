"""Mandiant ASM.
`parse_issue` is pure and fixture-tested; `fetch_issues` makes the live
call and is untested, same treatment as every other network-touching
fetcher in this project. Exact field names are best-effort against
Mandiant's publicly documented issue shape — verify against your own
tenant's export before relying on this in production.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from kiyooo.db.models import AssetType
from kiyooo.ingest.base import ImportedFinding

if TYPE_CHECKING:
    import httpx

_DEFAULT_BASE_URL = "https://api.expander.expanse.co"


def parse_issue(raw: dict[str, object]) -> ImportedFinding:
    issue_id = str(raw.get("id") or raw.get("uid"))
    issue_type = str(raw.get("issueType") or raw.get("headline") or "unknown")
    domain = raw.get("domain")
    ip = raw.get("ip")
    if domain:
        asset_type, asset_value = AssetType.SUBDOMAIN, str(domain)
    elif ip:
        asset_type, asset_value = AssetType.IP, str(ip)
    else:
        raise ValueError(f"mandiant issue {issue_id} has neither ip nor domain")

    return ImportedFinding(
        external_id=issue_id,
        vendor_issue_type=issue_type,
        title=str(raw.get("displayName") or raw.get("headline") or issue_type),
        vendor_severity=str(raw.get("severity", "unknown")),
        asset_type=asset_type,
        asset_value=asset_value,
        evidence_content=raw,
        raw_payload=raw,
    )


async def fetch_issues(
    client: httpx.AsyncClient,
    *,
    api_key: str,
    since: str | None = None,
    base_url: str = _DEFAULT_BASE_URL,
) -> list[dict[str, object]]:
    params: dict[str, str] = {}
    if since:
        params["inserted.gte"] = since
    resp = await client.get(
        f"{base_url}/api/library/issues",
        headers={"Authorization": f"Bearer {api_key}"},
        params=params,
        timeout=30.0,
    )
    resp.raise_for_status()
    data = resp.json()
    items = data.get("data", data if isinstance(data, list) else [])
    return list(items)
