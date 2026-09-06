from __future__ import annotations

from kiyooo.config import (
    ControlsFile,
    OrgContext,
    OwnershipOverride,
    OwnershipOverridesFile,
    ScopeConfig,
    TeamsFile,
)
from kiyooo.db.models import AssetType, OwnershipSource
from kiyooo.enrich.ownership import OwnershipEnrichmentContext, merge_existing, resolve_ownership
from kiyooo.enrich.ownership.merge import MergeOutcome
from tests.enrich.factories import make_asset
from tests.enrich.fakes import FakeAssetRepository, FakeOwnershipRepository


def _ctx(overrides: list[OwnershipOverride] | None = None) -> OwnershipEnrichmentContext:
    org_context = OrgContext(
        scope=ScopeConfig(org_name="testcorp"),
        teams=TeamsFile(),
        controls=ControlsFile(),
        categories={},
        ownership_overrides=OwnershipOverridesFile(overrides=overrides or []),
    )
    return OwnershipEnrichmentContext(
        org_context=org_context,
        cloud_matches=[],
        terraform_resources=[],
        codeowners=[],
        iac_repo_path=None,
        iac_manifest_file=None,
        email_to_owner={},
    )


async def test_resolve_ownership_with_no_sources_firing_is_orphan_and_persists_nothing() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "unowned.example.com")
    asset_repo = FakeAssetRepository([asset])
    ownership_repo = FakeOwnershipRepository()

    result = await resolve_ownership(asset, _ctx(), asset_repo, ownership_repo)

    assert result.outcome == MergeOutcome.ORPHAN
    assert await ownership_repo.list_for_asset(asset.id) == []


async def test_resolve_ownership_persists_manual_override_as_human_verified() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "legacy.example.com")
    asset_repo = FakeAssetRepository([asset])
    ownership_repo = FakeOwnershipRepository()
    ctx = _ctx(
        [
            OwnershipOverride(
                asset_value="legacy.example.com", owner_type="team", owner_ref="data-platform"
            )
        ]
    )

    result = await resolve_ownership(asset, ctx, asset_repo, ownership_repo)

    assert result.outcome == MergeOutcome.RESOLVED
    assert result.top is not None
    assert result.top.owner_ref == "data-platform"

    rows = await ownership_repo.list_for_asset(asset.id)
    assert len(rows) == 1
    assert rows[0].source == OwnershipSource.MANUAL
    assert rows[0].verified_by_human is True


async def test_resolve_ownership_rerun_updates_existing_row_not_duplicate() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "legacy.example.com")
    asset_repo = FakeAssetRepository([asset])
    ownership_repo = FakeOwnershipRepository()
    ctx = _ctx(
        [
            OwnershipOverride(
                asset_value="legacy.example.com", owner_type="team", owner_ref="data-platform"
            )
        ]
    )

    await resolve_ownership(asset, ctx, asset_repo, ownership_repo)
    await resolve_ownership(asset, ctx, asset_repo, ownership_repo)

    rows = await ownership_repo.list_for_asset(asset.id)
    assert len(rows) == 1


async def test_merge_existing_reports_without_rerunning_sources() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "legacy.example.com")
    ownership_repo = FakeOwnershipRepository()
    ownership_repo.seed(
        asset.id,
        source=OwnershipSource.MANUAL,
        owner_ref="data-platform",
        confidence=1.00,
        verified_by_human=True,
    )

    result = await merge_existing(asset.id, ownership_repo)

    assert result.outcome == MergeOutcome.RESOLVED
    assert result.top is not None
    assert result.top.owner_ref == "data-platform"


async def test_merge_existing_no_rows_is_orphan() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "unowned.example.com")
    ownership_repo = FakeOwnershipRepository()

    result = await merge_existing(asset.id, ownership_repo)

    assert result.outcome == MergeOutcome.ORPHAN
