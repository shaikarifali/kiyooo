"""nmap XML (`-oX`) importer — deferred, not implemented this stage. nmap
reports open ports, not categorized findings, so this would need its own
port -> vendor_issue_type synthesis (e.g. "open-port-3306") rather than a
straight field mapping like the other importers — a real design question,
not just missing plumbing, so it's left for a follow-up rather than
guessed at here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kiyooo.ingest.base import ImportedFinding


def parse_xml(raw: bytes) -> list[ImportedFinding]:
    raise NotImplementedError("nmap XML importer is not implemented — see this module's docstring")
