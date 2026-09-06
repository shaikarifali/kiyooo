from __future__ import annotations

import pytest

from kiyooo.db.models import AssetType
from kiyooo.ingest.adapters.mandiant import parse_issue


def test_parse_issue_with_domain() -> None:
    imported = parse_issue(
        {
            "id": "issue-1",
            "issueType": "InsecureFtp",
            "displayName": "Insecure FTP Server",
            "severity": "High",
            "domain": "ftp.example.com",
        }
    )
    assert imported.external_id == "issue-1"
    assert imported.vendor_issue_type == "InsecureFtp"
    assert imported.asset_type == AssetType.SUBDOMAIN
    assert imported.asset_value == "ftp.example.com"
    assert imported.vendor_severity == "High"


def test_parse_issue_with_ip_only() -> None:
    imported = parse_issue({"id": "issue-2", "issueType": "OpenPort", "ip": "203.0.113.5"})
    assert imported.asset_type == AssetType.IP
    assert imported.asset_value == "203.0.113.5"


def test_parse_issue_without_asset_raises() -> None:
    with pytest.raises(ValueError, match="neither ip nor domain"):
        parse_issue({"id": "issue-3", "issueType": "Unknown"})
