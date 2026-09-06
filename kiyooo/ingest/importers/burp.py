"""Burp Suite XML export importer — deferred, not implemented this stage.
Same reasoning as the other stub importers: no sample export on hand in
this sandbox to build and verify a real parser against.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kiyooo.ingest.base import ImportedFinding


def parse_xml(raw: bytes) -> list[ImportedFinding]:
    raise NotImplementedError("Burp importer is not implemented — see this module's docstring")
