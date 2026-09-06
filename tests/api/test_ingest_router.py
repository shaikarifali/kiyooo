"""`_would_map`'s own logic — the `/api/ingest/test` dry-run preview's
correctness depends entirely on this matching `ingest/pipeline.py::
ingest_finding`'s real mapped/unmapped decision, or the preview lies to a
user setting up a new source. Runs against the real `org-context.example`
(same one `KIYOOO_ORG_CONTEXT_PATH` points the running app at) rather
than a synthetic `OrgContext`, since building one by hand would let this
test drift from what the shipped mapping/categories actually say.
"""

from __future__ import annotations

from pathlib import Path

from kiyooo.api.routers.ingest import _would_map
from kiyooo.config import load_org_context

_ORG_CONTEXT_ROOT = Path(__file__).parents[2] / "org-context.example"


def test_would_map_true_for_known_mapping_and_matching_asset_type() -> None:
    ctx = load_org_context(_ORG_CONTEXT_ROOT)
    assert _would_map("SSL Certificate Expiry", "cert", ctx) is True


def test_would_map_false_when_category_does_not_apply_to_asset_type() -> None:
    """Regression: the preview must reject a category/asset-type mismatch
    the same way a real sync would — this exact combination was
    confirmed live to sync as unmapped even though a vendor_mapping.yaml
    entry exists for the issue type.
    """
    ctx = load_org_context(_ORG_CONTEXT_ROOT)
    assert _would_map("SSL Certificate Expiry", "subdomain", ctx) is False


def test_would_map_false_for_unknown_vendor_issue_type() -> None:
    ctx = load_org_context(_ORG_CONTEXT_ROOT)
    assert _would_map("something-no-mapping-entry-covers", "subdomain", ctx) is False
