from __future__ import annotations

import pytest

from kiyooo.db.models import AssetType
from kiyooo.ingest.adapters.tenable import parse_vulnerability


def test_parse_vulnerability_with_hostname() -> None:
    imported = parse_vulnerability(
        {
            "plugin": {"id": 12345, "name": "SSL Certificate Expiry"},
            "asset": {"hostname": "app.example.com", "uuid": "abc-123"},
            "severity": 3,
        }
    )
    assert imported.vendor_issue_type == "12345"
    assert imported.title == "SSL Certificate Expiry"
    assert imported.asset_type == AssetType.SUBDOMAIN
    assert imported.asset_value == "app.example.com"
    assert imported.vendor_severity == "high"
    assert imported.external_id == "12345:abc-123"


def test_parse_vulnerability_with_ipv4_only() -> None:
    imported = parse_vulnerability(
        {"plugin": {"id": 999}, "asset": {"ipv4": "10.0.0.5"}, "severity": 4}
    )
    assert imported.asset_type == AssetType.IP
    assert imported.asset_value == "10.0.0.5"
    assert imported.vendor_severity == "critical"


def test_parse_vulnerability_without_asset_raises() -> None:
    with pytest.raises(ValueError, match="no hostname or ipv4"):
        parse_vulnerability({"plugin": {"id": 1}, "asset": {}})
