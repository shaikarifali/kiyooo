"""GCP cloud enrichment — deferred, not implemented this stage.

Stage 3 names GCP alongside AWS and Azure, but only AWS's SDK
(`boto3`) ships a credential-free test double (`botocore.stub.Stubber`).
Google's client libraries have no equivalent this project can rely on the
same way, so implementing GCP here now would mean shipping code with no way
to verify it's actually correct in this sandbox — the same reasoning that
kept the DNS-audit-log ownership source out of this stage (see
`enrich/ownership/sources.py`). This module defines the interface so a real
implementation has a clear, structurally-ready home; it is not silently
missing.
"""

from __future__ import annotations

from kiyooo.enrich.cloud_aws import CloudResourceMatch


def enumerate_all() -> list[CloudResourceMatch]:
    raise NotImplementedError(
        "GCP cloud enrichment is not implemented — see this module's docstring"
    )
