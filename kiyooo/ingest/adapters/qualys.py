"""Qualys — deferred, not implemented this stage. Same reasoning as Stage
3's GCP/Azure stubs: no live tenant to verify a mapping against in this
sandbox. Qualys's VM/VMDR API (`GET /api/2.0/fo/asset/host/vm/detection/`,
XML) is the natural next adapter to build here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kiyooo.ingest.base import ImportedFinding


def parse_detection(raw: dict[str, object]) -> ImportedFinding:
    raise NotImplementedError("Qualys adapter is not implemented — see this module's docstring")
