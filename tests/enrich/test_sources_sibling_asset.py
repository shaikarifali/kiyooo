from __future__ import annotations

import pytest

from kiyooo.db.models import AssetType, OwnershipSource, OwnerType
from kiyooo.enrich.ownership.sources import sibling_asset
from tests.enrich.factories import make_asset
from tests.enrich.fakes import FakeAssetRepository, FakeOwnershipRepository


@pytest.mark.asyncio
async def test_sibling_with_human_confirmed_ownership_is_inherited() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "api.example.com")
    sibling = make_asset(AssetType.SUBDOMAIN, "www.example.com")

    asset_repo = FakeAssetRepository([asset, sibling])
    ownership_repo = FakeOwnershipRepository()
    ownership_repo.seed(
        sibling.id,
        source=OwnershipSource.MANUAL,
        owner_type=OwnerType.TEAM,
        owner_ref="web-team",
        verified_by_human=True,
    )

    candidate = await sibling_asset(asset, asset_repo, ownership_repo)
    assert candidate is not None
    assert candidate.source == OwnershipSource.SIBLING_ASSET
    assert candidate.owner_ref == "web-team"
    assert candidate.confidence == 0.70


@pytest.mark.asyncio
async def test_sibling_without_human_confirmed_ownership_returns_none() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "api.example.com")
    sibling = make_asset(AssetType.SUBDOMAIN, "www.example.com")

    asset_repo = FakeAssetRepository([asset, sibling])
    ownership_repo = FakeOwnershipRepository()
    ownership_repo.seed(
        sibling.id,
        source=OwnershipSource.TEAM_PATTERN,
        owner_ref="web-team",
        verified_by_human=False,
    )

    assert await sibling_asset(asset, asset_repo, ownership_repo) is None


@pytest.mark.asyncio
async def test_no_siblings_returns_none() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "api.example.com")

    asset_repo = FakeAssetRepository([asset])
    ownership_repo = FakeOwnershipRepository()

    assert await sibling_asset(asset, asset_repo, ownership_repo) is None


@pytest.mark.asyncio
async def test_self_is_never_treated_as_its_own_sibling() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "api.example.com")

    asset_repo = FakeAssetRepository([asset])
    ownership_repo = FakeOwnershipRepository()
    ownership_repo.seed(
        asset.id,
        source=OwnershipSource.MANUAL,
        owner_ref="web-team",
        verified_by_human=True,
    )

    assert await sibling_asset(asset, asset_repo, ownership_repo) is None


@pytest.mark.asyncio
async def test_non_dns_asset_type_returns_none() -> None:
    asset = make_asset(AssetType.IP, "93.184.216.34")

    asset_repo = FakeAssetRepository([asset])
    ownership_repo = FakeOwnershipRepository()

    assert await sibling_asset(asset, asset_repo, ownership_repo) is None


@pytest.mark.asyncio
async def test_bare_domain_with_no_second_level_label_returns_none() -> None:
    asset = make_asset(AssetType.DOMAIN, "localhost")

    asset_repo = FakeAssetRepository([asset])
    ownership_repo = FakeOwnershipRepository()

    assert await sibling_asset(asset, asset_repo, ownership_repo) is None
