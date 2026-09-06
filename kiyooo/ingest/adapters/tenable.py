"""Tenable.io / Nessus. `parse_vulnerability` is pure
and fixture-tested against Tenable.io's `/workbenches/vulnerabilities`
shape; `fetch_vulnerabilities` makes the live call and is untested.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from kiyooo.db.models import AssetType
from kiyooo.ingest.base import ImportedFinding

if TYPE_CHECKING:
    import httpx

_DEFAULT_BASE_URL = "https://cloud.tenable.com"
_SEVERITY_NAMES = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def parse_vulnerability(raw: dict[str, object]) -> ImportedFinding:
    plugin_raw = raw.get("plugin", {})
    asset_raw = raw.get("asset", {})
    plugin = plugin_raw if isinstance(plugin_raw, dict) else {}
    asset = asset_raw if isinstance(asset_raw, dict) else {}

    plugin_id = str(plugin.get("id", "unknown"))
    hostname = asset.get("hostname") or asset.get("fqdn")
    ipv4 = asset.get("ipv4")
    if hostname:
        asset_type, asset_value = AssetType.SUBDOMAIN, str(hostname)
    elif ipv4:
        asset_type, asset_value = AssetType.IP, str(ipv4)
    else:
        raise ValueError(f"tenable vulnerability for plugin {plugin_id} has no hostname or ipv4")

    severity_num = raw.get("severity", 0)
    vendor_severity = _SEVERITY_NAMES.get(
        int(severity_num) if isinstance(severity_num, int) else 0, "unknown"
    )

    return ImportedFinding(
        external_id=f"{plugin_id}:{asset.get('uuid', asset_value)}",
        vendor_issue_type=plugin_id,
        title=str(plugin.get("name", f"Plugin {plugin_id}")),
        vendor_severity=vendor_severity,
        asset_type=asset_type,
        asset_value=asset_value,
        evidence_content=raw,
        raw_payload=raw,
    )


async def fetch_vulnerabilities(
    client: httpx.AsyncClient,
    *,
    access_key: str,
    secret_key: str,
    base_url: str = _DEFAULT_BASE_URL,
) -> list[dict[str, object]]:
    resp = await client.get(
        f"{base_url}/workbenches/vulnerabilities",
        headers={"X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}"},
        timeout=30.0,
    )
    resp.raise_for_status()
    data = resp.json()
    return list(data.get("vulnerabilities", []))
