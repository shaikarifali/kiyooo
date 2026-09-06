"""Generic CSV importer — for any vendor export
without a dedicated adapter. Column names are supplied by the caller
(`kiyooo ingest --file x.csv --asset-col host ...`), never guessed at —
an org's export columns aren't something this module can know in advance.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from typing import TYPE_CHECKING

from kiyooo.ingest.base import ImportedFinding

if TYPE_CHECKING:
    from kiyooo.db.models import AssetType


@dataclass(frozen=True, slots=True)
class CsvColumnMapping:
    asset_col: str
    issue_type_col: str
    external_id_col: str | None = None
    title_col: str | None = None
    severity_col: str | None = None


def parse_csv(
    raw: bytes, *, asset_type: AssetType, columns: CsvColumnMapping
) -> list[ImportedFinding]:
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig")))
    findings: list[ImportedFinding] = []
    for i, row in enumerate(reader):
        asset_value = row.get(columns.asset_col)
        issue_type = row.get(columns.issue_type_col)
        if not asset_value or not issue_type:
            continue
        external_id = (columns.external_id_col and row.get(columns.external_id_col)) or (
            f"csv-row-{i}"
        )
        title = (columns.title_col and row.get(columns.title_col)) or issue_type
        severity = (columns.severity_col and row.get(columns.severity_col)) or "unknown"
        findings.append(
            ImportedFinding(
                external_id=external_id,
                vendor_issue_type=issue_type,
                title=title,
                vendor_severity=severity,
                asset_type=asset_type,
                asset_value=asset_value,
                evidence_content=dict(row),
                raw_payload=dict(row),
            )
        )
    return findings
