"""httpx evidence -> host `SERVES` http_service."""

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
            relation=AssetEdgeRelation.SERVES,
            own_is_src=False,  # host --SERVES--> http_service (item's own asset)
        )
    ]
