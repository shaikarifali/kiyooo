from __future__ import annotations

from kiyooo.config import VendorMappingEntry, VendorMappingFile
from kiyooo.ingest.mapper import map_category


def test_map_category_found() -> None:
    mapping = VendorMappingFile(
        mappings=[VendorMappingEntry(vendor_issue_type="InsecureFtp", category_id="exposed-ftp")]
    )
    assert map_category("InsecureFtp", mapping) == "exposed-ftp"


def test_map_category_not_found() -> None:
    mapping = VendorMappingFile(mappings=[])
    assert map_category("Unknown", mapping) is None
