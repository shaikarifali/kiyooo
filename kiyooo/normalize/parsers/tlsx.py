"""tlsx evidence -> cert `ISSUED_FOR` host."""

from __future__ import annotations

from kiyooo.db.models import AssetEdgeRelation
from kiyooo.recon.base import ParsedEvidence

from .types import EdgeHint, resolve_related_value


def derive_edges(item: ParsedEvidence) -> list[EdgeHint]:
    host = item.content.get("host")
    if not host:
        return []
    return [
        EdgeHint(
            related_asset_value=resolve_related_value(str(host)),
            relation=AssetEdgeRelation.ISSUED_FOR,
            own_is_src=True,  # cert (item's own asset) --ISSUED_FOR--> host
        )
    ]
