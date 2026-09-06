"""naabu evidence -> tcp_service `HOSTED_ON` host/ip."""

from __future__ import annotations

from kiyooo.db.models import AssetEdgeRelation
from kiyooo.recon.base import ParsedEvidence

from .types import EdgeHint, resolve_related_value


def derive_edges(item: ParsedEvidence) -> list[EdgeHint]:
    host = item.content.get("host") or item.content.get("ip")
    if not host:
        return []
    return [
        EdgeHint(
            related_asset_value=resolve_related_value(str(host)),
            relation=AssetEdgeRelation.HOSTED_ON,
            own_is_src=True,  # tcp_service (item's own asset) --HOSTED_ON--> host
        )
    ]
