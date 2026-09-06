from __future__ import annotations

from kiyooo.config import TeamDefinition, TeamOwnership
from kiyooo.db.models import AssetType
from kiyooo.enrich.cloud_aws import CloudResourceMatch
from kiyooo.enrich.ownership.sources import teams_pattern
from tests.enrich.factories import make_asset


def _team(
    team_id: str,
    *,
    dns_patterns: list[str] | None = None,
    cloud_accounts: list[str] | None = None,
    cloud_tags: dict[str, str] | None = None,
) -> TeamDefinition:
    return TeamDefinition(
        id=team_id,
        manager=f"{team_id}-manager@example.com",
        owns=TeamOwnership(
            dns_patterns=dns_patterns or [],
            cloud_accounts=cloud_accounts or [],
            cloud_tags=cloud_tags or {},
        ),
    )


def test_dns_pattern_match() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "api.data.example.com")
    team = _team("data-platform", dns_patterns=["*.data.example.com"])
    candidate = teams_pattern(asset, [team])
    assert candidate is not None
    assert candidate.owner_ref == "data-platform"
    assert candidate.confidence == 0.80


def test_dns_pattern_no_match_returns_none() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "api.other.example.com")
    team = _team("data-platform", dns_patterns=["*.data.example.com"])
    assert teams_pattern(asset, [team]) is None


def test_cloud_account_match() -> None:
    asset = make_asset(AssetType.IP, "93.184.216.34")
    match = CloudResourceMatch(
        asset_value="93.184.216.34",
        provider="aws",
        account_id="111122223333",
        resource_id="i-0abc",
        resource_type="ec2_instance",
        tags={},
    )
    team = _team("data-platform", cloud_accounts=["111122223333"])
    candidate = teams_pattern(asset, [team], [match])
    assert candidate is not None
    assert candidate.owner_ref == "data-platform"


def test_cloud_tags_match() -> None:
    asset = make_asset(AssetType.IP, "93.184.216.34")
    match = CloudResourceMatch(
        asset_value="93.184.216.34",
        provider="aws",
        account_id="111122223333",
        resource_id="i-0abc",
        resource_type="ec2_instance",
        tags={"CostCenter": "cc-42"},
    )
    team = _team("data-platform", cloud_tags={"CostCenter": "cc-42"})
    candidate = teams_pattern(asset, [team], [match])
    assert candidate is not None
    assert candidate.owner_ref == "data-platform"


def test_first_matching_team_wins() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "api.data.example.com")
    team_a = _team("data-platform", dns_patterns=["*.data.example.com"])
    team_b = _team("appsec", dns_patterns=["*.data.example.com"])
    candidate = teams_pattern(asset, [team_a, team_b])
    assert candidate is not None
    assert candidate.owner_ref == "data-platform"


def test_no_teams_returns_none() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "api.data.example.com")
    assert teams_pattern(asset, []) is None
