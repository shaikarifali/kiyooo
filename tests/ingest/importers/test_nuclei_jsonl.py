from __future__ import annotations

from kiyooo.db.models import AssetType
from kiyooo.ingest.importers.nuclei_jsonl import parse_jsonl, parse_line


def test_parse_line_matched() -> None:
    raw = b'{"template-id":"tech-detect-nginx","info":{"name":"nginx Detection","severity":"info"},"host":"https://www.example.com","matched-at":"https://www.example.com","type":"http"}'
    imported = parse_line(raw)
    assert imported is not None
    assert imported.vendor_issue_type == "tech-detect-nginx"
    assert imported.asset_type == AssetType.URL
    assert imported.asset_value == "https://www.example.com"
    assert imported.vendor_severity == "info"


def test_parse_line_blank_returns_none() -> None:
    assert parse_line(b"") is None
    assert parse_line(b"   ") is None


def test_parse_line_malformed_json_returns_none() -> None:
    assert parse_line(b"not json") is None


def test_parse_jsonl_skips_bad_lines() -> None:
    raw = (
        b'{"template-id":"a","host":"https://a.example.com","matched-at":"https://a.example.com"}\n'
        b"not json\n"
        b'{"template-id":"b","host":"https://b.example.com","matched-at":"https://b.example.com"}\n'
    )
    findings = parse_jsonl(raw)
    assert len(findings) == 2
    assert {f.vendor_issue_type for f in findings} == {"a", "b"}
