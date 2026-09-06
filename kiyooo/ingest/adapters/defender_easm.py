"""Microsoft Defender EASM — deferred, not implemented this stage. Needs
an Azure tenant + EASM workspace to develop and verify a mapping against —
same reasoning as the other stub adapters here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kiyooo.ingest.base import ImportedFinding


def parse_asset_finding(raw: dict[str, object]) -> ImportedFinding:
    raise NotImplementedError(
        "Defender EASM adapter is not implemented — see this module's docstring"
    )
