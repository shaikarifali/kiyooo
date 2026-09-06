"""CrowdStrike (Falcon Surface / Spotlight) — deferred, not implemented
this stage. Needs a live tenant to develop and verify a mapping against —
same reasoning as the other stub adapters here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kiyooo.ingest.base import ImportedFinding


def parse_finding(raw: dict[str, object]) -> ImportedFinding:
    raise NotImplementedError(
        "CrowdStrike adapter is not implemented — see this module's docstring"
    )
