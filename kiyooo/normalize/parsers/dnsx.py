"""dnsx evidence -> host `RESOLVES_TO` ip."""

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
            relation=AssetEdgeRelation.RESOLVES_TO,
            own_is_src=False,  # host --RESOLVES_TO--> ip (item's own asset)
        )
    ]
