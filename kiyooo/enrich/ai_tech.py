"""AI-tech fingerprint promotion — same pattern as
`enrich/tech.py`'s wappalyzer-tag promotion, pointed at
`detect/ai_fingerprints.py`'s AI-specific signature catalog instead
(Ollama, Chroma, MCP, ... aren't in httpx's generic tech-detect database).
Merged across scans, never overwritten, for the same reason `enrich/
tech.py` merges: a signature not re-observed this scan (a flaky probe, a
service restart mid-scan) shouldn't silently disappear from the asset's
record.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from kiyooo.detect.ai_fingerprints import load_catalog, match_signatures

if TYPE_CHECKING:
    from kiyooo.db.models import Asset, Evidence


def merge_ai_tech(asset: Asset, evidence: list[Evidence]) -> list[str]:
    existing = asset.attributes.get("ai_tech", [])
    observed: set[str] = {str(t) for t in existing} if isinstance(existing, list) else set()
    observed.update(match_signatures(evidence, catalog=load_catalog()))
    return sorted(observed)


def apply_ai_tech(asset: Asset, evidence: list[Evidence]) -> None:
    """Reassigns `asset.attributes` rather than mutating it in place —
    SQLAlchemy's change tracking on a plain JSONB column only notices
    attribute reassignment, not in-place dict mutation (same note
    `enrich/tech.py:apply_tech` carries).
    """
    merged = merge_ai_tech(asset, evidence)
    asset.attributes = {**asset.attributes, "ai_tech": merged}
