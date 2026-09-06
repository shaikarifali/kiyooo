from __future__ import annotations

from kiyooo.config import (
    ControlsFile,
    OrgContext,
    OwnershipOverride,
    OwnershipOverridesFile,
    ScopeConfig,
    TeamsFile,
)
from kiyooo.db.models import AssetType, OwnershipSource, OwnerType
from kiyooo.enrich.cloud_aws import CloudResourceMatch
from kiyooo.enrich.ownership.sources import cloud_tag, manual_override
from tests.enrich.factories import make_asset


def _org_context(overrides: list[OwnershipOverride]) -> OrgContext:
    return OrgContext(
        scope=ScopeConfig(org_name="testcorp"),
        teams=TeamsFile(),
        controls=ControlsFile(),
        categories={},
        ownership_overrides=OwnershipOverridesFile(overrides=overrides),
    )


def test_manual_override_matches_by_asset_value() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "legacy.example.com")
    org_context = _org_context(
        [
            OwnershipOverride(
                asset_value="legacy.example.com", owner_type="team", owner_ref="data-platform"
            )
        ]
    )
    candidate = manual_override(asset, org_context)
    assert candidate is not None
    assert candidate.source == OwnershipSource.MANUAL
    assert candidate.owner_ref == "data-platform"
    assert candidate.confidence == 1.00


def test_manual_override_no_match_returns_none() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "other.example.com")
    org_context = _org_context(
        [
            OwnershipOverride(
                asset_value="legacy.example.com", owner_type="team", owner_ref="data-platform"
            )
        ]
    )
    assert manual_override(asset, org_context) is None


def test_cloud_tag_reads_owner_tag() -> None:
    asset = make_asset(AssetType.IP, "93.184.216.34")
    match = CloudResourceMatch(
        asset_value="93.184.216.34",
        provider="aws",
        account_id="123456789012",
        resource_id="i-0abc",
        resource_type="ec2_instance",
        tags={"Owner": "data-platform", "Environment": "prod"},
    )
    candidate = cloud_tag(asset, [match])
    assert candidate is not None
    assert candidate.owner_ref == "data-platform"
    assert candidate.owner_type == OwnerType.TEAM
    assert candidate.confidence == 0.95


def test_cloud_tag_falls_back_to_team_tag() -> None:
    asset = make_asset(AssetType.IP, "93.184.216.34")
    match = CloudResourceMatch(
        asset_value="93.184.216.34",
        provider="aws",
        account_id="123456789012",
        resource_id="i-0abc",
        resource_type="ec2_instance",
        tags={"Team": "appsec"},
    )
    candidate = cloud_tag(asset, [match])
    assert candidate is not None
    assert candidate.owner_ref == "appsec"


def test_cloud_tag_no_matching_resource_returns_none() -> None:
    asset = make_asset(AssetType.IP, "93.184.216.34")
    match = CloudResourceMatch(
        asset_value="10.0.0.1",
        provider="aws",
        account_id="123456789012",
        resource_id="i-0abc",
        resource_type="ec2_instance",
        tags={"Owner": "data-platform"},
    )
    assert cloud_tag(asset, [match]) is None


def test_cloud_tag_resource_with_no_owner_or_team_tag_returns_none() -> None:
    asset = make_asset(AssetType.IP, "93.184.216.34")
    match = CloudResourceMatch(
        asset_value="93.184.216.34",
        provider="aws",
        account_id="123456789012",
        resource_id="i-0abc",
        resource_type="ec2_instance",
        tags={"Environment": "prod"},
    )
    assert cloud_tag(asset, [match]) is None
