"""Wiz — deferred, not implemented this stage. Wiz's GraphQL API needs a
tenant to develop and verify a query/mapping against, which this sandbox
doesn't have — same reasoning as the other stub adapters here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kiyooo.ingest.base import ImportedFinding


def parse_issue(raw: dict[str, object]) -> ImportedFinding:
    raise NotImplementedError("Wiz adapter is not implemented — see this module's docstring")
