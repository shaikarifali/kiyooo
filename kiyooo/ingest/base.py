"""Common shape every vendor adapter / file importer maps onto (the design
Stage 1b). "We ingest their findings; we do not inherit their severity" —
`vendor_severity` is carried through for reference only; `ingest/pipeline.py`
never reads it to set `Finding.raw_severity`, only `category.severity_base`
does that, same as `detect/engine.py`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kiyooo.db.models import AssetType


@dataclass(frozen=True, slots=True)
class ImportedFinding:
    external_id: str
    vendor_issue_type: str
    title: str
    vendor_severity: str
    asset_type: AssetType
    asset_value: str
    evidence_content: dict[str, object]
    raw_payload: dict[str, object]
