from __future__ import annotations

from kiyooo.db.models import AssetType
from kiyooo.ingest.importers.csv_generic import CsvColumnMapping, parse_csv

_COLUMNS = CsvColumnMapping(
    asset_col="Host",
    issue_type_col="Type",
    external_id_col="ID",
    title_col="Title",
    severity_col="Severity",
)


def test_parse_csv_maps_rows() -> None:
    raw = b"ID,Host,Type,Title,Severity\n1,app.example.com,xss,Reflected XSS,high\n"
    findings = parse_csv(raw, asset_type=AssetType.SUBDOMAIN, columns=_COLUMNS)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.external_id == "1"
    assert finding.vendor_issue_type == "xss"
    assert finding.title == "Reflected XSS"
    assert finding.vendor_severity == "high"
    assert finding.asset_value == "app.example.com"


def test_parse_csv_skips_rows_missing_asset_or_type() -> None:
    raw = b"ID,Host,Type,Title,Severity\n1,,xss,X,high\n2,app.example.com,,Y,high\n"
    findings = parse_csv(raw, asset_type=AssetType.SUBDOMAIN, columns=_COLUMNS)
    assert findings == []


def test_parse_csv_generates_row_id_without_external_id_col() -> None:
    columns = CsvColumnMapping(asset_col="Host", issue_type_col="Type")
    raw = b"Host,Type\napp.example.com,xss\n"
    findings = parse_csv(raw, asset_type=AssetType.SUBDOMAIN, columns=columns)
    assert findings[0].external_id == "csv-row-0"
    assert findings[0].title == "xss"  # falls back to issue_type
    assert findings[0].vendor_severity == "unknown"
