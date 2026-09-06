"""Tech fingerprint promotion.

httpx's evidence already carries a wappalyzer-style `tech[]` array (Stage 1's
`-tech-detect` flag, already surfaced in Stage 2's per-scan snapshot state) —
this promotes it onto the `Asset` row itself (`asset.attributes["tech"]`),
merged across scans rather than overwritten. A tech observed once and not
re-detected later (a flaky scan, a template change, a cache-busted request)
shouldn't silently disappear from the asset's record.
"""

from __future__ import annotations

from kiyooo.db.models import Asset, Evidence, EvidenceKind


def merge_tech(asset: Asset, evidence: list[Evidence]) -> list[str]:
    existing = asset.attributes.get("tech", [])
    observed: set[str] = {str(t) for t in existing} if isinstance(existing, list) else set()

    for item in evidence:
        if item.kind != EvidenceKind.HTTP_RESPONSE:
            continue
        content = item.content_inline or {}
        tech = content.get("tech") or []
        if isinstance(tech, list):
            observed.update(str(t) for t in tech)

    return sorted(observed)


def apply_tech(asset: Asset, evidence: list[Evidence]) -> None:
    """Reassigns `asset.attributes` (rather than mutating it in place) —
    SQLAlchemy's change tracking on a plain JSONB column only notices
    attribute reassignment, not in-place dict mutation.
    """
    merged = merge_tech(asset, evidence)
    asset.attributes = {**asset.attributes, "tech": merged}
