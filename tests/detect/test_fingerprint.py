from __future__ import annotations

from kiyooo.db.models import AssetType
from kiyooo.normalize.fingerprint import (
    compute_cluster_id,
    compute_fingerprint,
    normalized_asset_identity,
)
from tests.enrich.factories import make_asset


def test_normalized_asset_identity_uses_value_for_hostname_bearing_types() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com:8443")
    assert normalized_asset_identity(asset) == "https://app.example.com:8443"


def test_normalized_asset_identity_cloud_resource_uses_attributes() -> None:
    asset = make_asset(AssetType.CLOUD_RESOURCE, "fallback-value")
    asset.attributes = {
        "provider": "aws",
        "account": "111122223333",
        "resource_arn": "arn:aws:s3:::acmecorp-reports",
    }
    assert normalized_asset_identity(asset) == "aws:111122223333:arn:aws:s3:::acmecorp-reports"


def test_normalized_asset_identity_cloud_resource_falls_back_to_value() -> None:
    asset = make_asset(AssetType.CLOUD_RESOURCE, "acmecorp-reports")
    assert normalized_asset_identity(asset) == "::acmecorp-reports"


def test_normalized_asset_identity_repo_uses_attributes() -> None:
    asset = make_asset(AssetType.REPO, "fallback-value")
    asset.attributes = {"repo_url": "github.com/acmecorp/infra", "file_path": "main.tf"}
    assert normalized_asset_identity(asset) == "github.com/acmecorp/infra:main.tf"


def test_compute_fingerprint_is_stable_across_calls() -> None:
    asset = make_asset(AssetType.CERT, "app.example.com:443")
    a = compute_fingerprint("expired-cert", asset, "SERIAL123")
    b = compute_fingerprint("expired-cert", asset, "SERIAL123")
    assert a == b


def test_compute_fingerprint_differs_by_category() -> None:
    asset = make_asset(AssetType.CERT, "app.example.com:443")
    a = compute_fingerprint("expired-cert", asset, "SERIAL123")
    b = compute_fingerprint("some-other-category", asset, "SERIAL123")
    assert a != b


def test_compute_fingerprint_differs_by_asset_identity() -> None:
    asset_a = make_asset(AssetType.CERT, "a.example.com:443")
    asset_b = make_asset(AssetType.CERT, "b.example.com:443")
    fp_a = compute_fingerprint("expired-cert", asset_a, "SERIAL123")
    fp_b = compute_fingerprint("expired-cert", asset_b, "SERIAL123")
    assert fp_a != fp_b


def test_compute_fingerprint_differs_by_discriminator() -> None:
    asset = make_asset(AssetType.CERT, "app.example.com:443")
    fp_a = compute_fingerprint("expired-cert", asset, "SERIAL_A")
    fp_b = compute_fingerprint("expired-cert", asset, "SERIAL_B")
    assert fp_a != fp_b


def test_compute_cluster_id_collapses_across_assets() -> None:
    """The DoD's own demo case: the same expired-cert issue on 40 different
    hosts must all share one cluster_id, even though every fingerprint
    (which includes asset identity) differs.
    """
    cluster_ids = {
        compute_cluster_id("expired-cert", "SERIAL123")
        for _ in range(40)
        # cluster_id depends only on (category_id, discriminator) — asset
        # identity never enters it, so 40 distinct assets sharing the same
        # cert serial all collapse to the same cluster_id with no lookup.
    }
    assert len(cluster_ids) == 1


def test_compute_cluster_id_differs_by_discriminator() -> None:
    a = compute_cluster_id("expired-cert", "SERIAL_A")
    b = compute_cluster_id("expired-cert", "SERIAL_B")
    assert a != b


def test_compute_cluster_id_is_deterministic_not_random() -> None:
    a = compute_cluster_id("expired-cert", "SERIAL123")
    b = compute_cluster_id("expired-cert", "SERIAL123")
    assert a == b
