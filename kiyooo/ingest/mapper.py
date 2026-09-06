"""vendor_issue_type -> our category_id. Pure lookup
against the org-context mapping table — an unmapped vendor issue type is
not an error, it's a work item (`kiyooo ingest --report-unmapped`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kiyooo.config import VendorMappingFile


def map_category(vendor_issue_type: str, mapping: VendorMappingFile) -> str | None:
    for entry in mapping.mappings:
        if entry.vendor_issue_type == vendor_issue_type:
            return entry.category_id
    return None
