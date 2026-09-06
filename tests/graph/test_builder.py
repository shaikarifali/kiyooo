from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from kiyooo.db.models import AssetType
from kiyooo.graph.builder import decay_inactive_assets, upsert_asset
from tests.graph.fakes import FakeAssetRepository, FakeScanRunRepository


async def test_upsert_asset_canonicalizes_before_storing() -> None:
    repo = FakeAssetRepository()
    asset = await upsert_asset(repo, AssetType.DOMAIN, "WWW.Example.COM.", confidence_in_scope=1.0)
    assert asset.value == "www.example.com"


async def test_upsert_asset_is_idempotent_across_case_variants() -> None:
    repo = FakeAssetRepository()
    first = await upsert_asset(repo, AssetType.DOMAIN, "Example.com", confidence_in_scope=1.0)
    second = await upsert_asset(repo, AssetType.DOMAIN, "EXAMPLE.COM", confidence_in_scope=1.0)
    assert first.id == second.id
    assert len(repo._by_id) == 1


async def test_upsert_asset_updates_last_seen_on_rescan() -> None:
    repo = FakeAssetRepository()
    first = await upsert_asset(repo, AssetType.DOMAIN, "example.com", confidence_in_scope=1.0)
    original_last_seen = first.last_seen
    second = await upsert_asset(repo, AssetType.DOMAIN, "example.com", confidence_in_scope=1.0)
    assert second.last_seen >= original_last_seen


async def test_decay_marks_unseen_assets_inactive_after_threshold() -> None:
    asset_repo = FakeAssetRepository()
    scan_run_repo = FakeScanRunRepository()

    old_time = datetime.now(UTC) - timedelta(days=30)
    stale_asset = await upsert_asset(
        asset_repo, AssetType.SUBDOMAIN, "old.example.com", confidence_in_scope=1.0
    )
    stale_asset.last_seen = old_time

    # 3 completed scans, all more recent than the stale asset's last_seen.
    now = datetime.now(UTC)
    scan_run_repo.add_completed(uuid4(), now - timedelta(days=3))
    scan_run_repo.add_completed(uuid4(), now - timedelta(days=2))
    scan_run_repo.add_completed(uuid4(), now - timedelta(days=1))

    decayed = await decay_inactive_assets(asset_repo, scan_run_repo, scan_threshold=3)

    assert stale_asset in decayed
    assert stale_asset.is_active is False


async def test_decay_does_nothing_with_insufficient_scan_history() -> None:
    asset_repo = FakeAssetRepository()
    scan_run_repo = FakeScanRunRepository()

    old_time = datetime.now(UTC) - timedelta(days=30)
    stale_asset = await upsert_asset(
        asset_repo, AssetType.SUBDOMAIN, "old.example.com", confidence_in_scope=1.0
    )
    stale_asset.last_seen = old_time

    # Only 2 completed scans exist; threshold is 3 — not enough history.
    now = datetime.now(UTC)
    scan_run_repo.add_completed(uuid4(), now - timedelta(days=2))
    scan_run_repo.add_completed(uuid4(), now - timedelta(days=1))

    decayed = await decay_inactive_assets(asset_repo, scan_run_repo, scan_threshold=3)

    assert decayed == []
    assert stale_asset.is_active is True


async def test_recently_seen_asset_is_not_decayed() -> None:
    asset_repo = FakeAssetRepository()
    scan_run_repo = FakeScanRunRepository()

    fresh_asset = await upsert_asset(
        asset_repo, AssetType.SUBDOMAIN, "fresh.example.com", confidence_in_scope=1.0
    )

    now = datetime.now(UTC)
    scan_run_repo.add_completed(uuid4(), now - timedelta(days=3))
    scan_run_repo.add_completed(uuid4(), now - timedelta(days=2))
    scan_run_repo.add_completed(uuid4(), now - timedelta(days=1))

    decayed = await decay_inactive_assets(asset_repo, scan_run_repo, scan_threshold=3)

    assert fresh_asset not in decayed
    assert fresh_asset.is_active is True


async def test_get_or_create_reactivates_a_decayed_asset() -> None:
    repo = FakeAssetRepository()
    asset = await upsert_asset(
        repo, AssetType.SUBDOMAIN, "reappearing.example.com", confidence_in_scope=1.0
    )
    await repo.mark_inactive([asset])
    assert asset.is_active is False

    reseen = await upsert_asset(
        repo, AssetType.SUBDOMAIN, "reappearing.example.com", confidence_in_scope=1.0
    )
    assert reseen.id == asset.id
    assert reseen.is_active is True
