"""Finding fingerprint + cluster key.

fingerprint = sha256(category_id | normalized_asset_identity | discriminator)

Never includes a rotating IP for anything reachable via a stable hostname —
`Asset.value` for hostname-bearing types is already Stage 2's canonicalized
identity (`normalize/asset_identity.py`), which resolves to the DNS name,
not whichever IP answered on a given scan. That's what makes this safe to
build directly from `asset.value` for most types.

The same expired cert reported by nuclei, tlsx, and an imported Qualys scan
must collapse into one `finding` row — the fingerprint deliberately excludes
the detecting tool (`detector`/`detector_ref` live on `Finding` for
reference, never in the fingerprint).
"""

from __future__ import annotations

import hashlib
import uuid

from kiyooo.db.models import Asset, AssetType

# Fixed, arbitrary constant — any stable UUID works as a uuid5 namespace, it
# just has to never change, so cluster_id stays deterministic across runs.
_CLUSTER_NAMESPACE = uuid.UUID("6a3e1b6a-6b3e-4b1a-9c1e-3f6c8f8b9a10")


def normalized_asset_identity(asset: Asset) -> str:
    """Per the design's fingerprint rule:

    http_service  -> scheme://host:port (host = the DNS name)
    tcp_service   -> stable_host_id:port/proto
    cloud_resource-> cloud_provider:account:resource_arn
    repo          -> repo_url:file_path

    `cloud_resource` and `repo` assets carry their identity components in
    `attributes` rather than `value` (no adapter emits either asset type
    yet — see `enrich/cloud_aws.py`'s docstring on the same gap) — this
    falls back to `asset.value` if those attributes are absent rather than
    raising, since an incomplete identity is still better than no
    fingerprint at all.
    """
    if asset.type == AssetType.CLOUD_RESOURCE:
        provider = asset.attributes.get("provider", "")
        account = asset.attributes.get("account", "")
        resource_arn = asset.attributes.get("resource_arn", asset.value)
        return f"{provider}:{account}:{resource_arn}"
    if asset.type == AssetType.REPO:
        repo_url = asset.attributes.get("repo_url", asset.value)
        file_path = asset.attributes.get("file_path", "")
        return f"{repo_url}:{file_path}"
    return asset.value


def compute_fingerprint(category_id: str, asset: Asset, discriminator: str) -> str:
    identity = normalized_asset_identity(asset)
    raw = f"{category_id}|{identity}|{discriminator}"
    return hashlib.sha256(raw.encode()).hexdigest()


def compute_cluster_id(category_id: str, discriminator: str) -> uuid.UUID:
    """The fingerprint's asset-identity component removed — same category +
    same discriminator across N assets always yields the same `cluster_id`,
    deterministically, with no side table or extra lookup needed to find
    "does a cluster already exist for this issue."
    """
    return uuid.uuid5(_CLUSTER_NAMESPACE, f"{category_id}|{discriminator}")
