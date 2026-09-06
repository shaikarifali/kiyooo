"""nuclei JSONL file importer — the same output
shape `recon/adapters/nuclei.py` parses live, replayed from a file the
user already has (a scan run elsewhere, CI output, an older export).
"""

from __future__ import annotations

import json

from kiyooo.db.models import AssetType
from kiyooo.ingest.base import ImportedFinding


def parse_line(raw: bytes) -> ImportedFinding | None:
    stripped = raw.strip()
    if not stripped:
        return None
    try:
        record = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    matched_at = record.get("matched-at") or record.get("host")
    if not matched_at:
        return None

    template_id = str(record.get("template-id", "unknown"))
    info = record.get("info") if isinstance(record.get("info"), dict) else {}
    return ImportedFinding(
        external_id=f"{template_id}:{matched_at}",
        vendor_issue_type=template_id,
        title=str(info.get("name", template_id)),
        vendor_severity=str(info.get("severity", "unknown")),
        asset_type=AssetType.URL,
        asset_value=str(matched_at),
        evidence_content=record,
        raw_payload=record,
    )


def parse_jsonl(raw: bytes) -> list[ImportedFinding]:
    findings: list[ImportedFinding] = []
    for line in raw.splitlines():
        imported = parse_line(line)
        if imported is not None:
            findings.append(imported)
    return findings
