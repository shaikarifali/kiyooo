"""Evidence-driven `AssetEdge` derivation.

Each tool that implies a relationship between two assets gets a small
`derive_edges(item) -> list[EdgeHint]` function here, keyed by `source_tool`.
`kiyooo.recon.orchestrator.EvidenceWriter` calls the matching one for every
evidence item it writes, using the evidence content Stage 1 already
collected — no re-fetching, no changes to the Stage 1 adapters themselves.

Not every Stage 1 adapter has a parser here — only where the evidence's own
content reliably identifies both ends of the edge. `katana` is deliberately
absent: its evidence doesn't carry an unambiguous back-reference to the
`HTTP_SERVICE` it crawled from in the shape this project's parser extracts,
and guessing would produce edges that merely look plausible. That's a known
gap, not a silent approximation — add a `katana.py` here once its real
schema is confirmed against live output.
"""

from __future__ import annotations

from collections.abc import Callable

from kiyooo.recon.base import ParsedEvidence

from .dnsx import derive_edges as _dnsx_edges
from .httpx import derive_edges as _httpx_edges
from .naabu import derive_edges as _naabu_edges
from .tlsx import derive_edges as _tlsx_edges
from .types import EdgeHint

_PARSERS: dict[str, Callable[[ParsedEvidence], list[EdgeHint]]] = {
    "dnsx": _dnsx_edges,
    "tlsx": _tlsx_edges,
    "naabu": _naabu_edges,
    "httpx": _httpx_edges,
}


def derive_edges(source_tool: str, item: ParsedEvidence) -> list[EdgeHint]:
    parser = _PARSERS.get(source_tool)
    if parser is None:
        return []
    return parser(item)
