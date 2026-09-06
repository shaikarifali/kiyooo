"""Azure cloud enrichment — deferred, not implemented this stage.

See `cloud_gcp.py`'s docstring — same reasoning applies: no credential-free
way to test Azure SDK calls in this sandbox, so this stays an interface, not
an unverifiable implementation.
"""

from __future__ import annotations

from kiyooo.enrich.cloud_aws import CloudResourceMatch


def enumerate_all() -> list[CloudResourceMatch]:
    raise NotImplementedError(
        "Azure cloud enrichment is not implemented — see this module's docstring"
    )
