"""diff/engine.py integration tests using fake repos — the full pipeline
(snapshot -> diff) rather than diff.rules.detect() in isolation (see
tests/diff/test_rules.py for that). This is the Stage 2 DoD scenario run
through the actual code path `kiyooo scan` uses.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kiyooo.db.models import Asset, AssetSnapshot, AssetType, ChangeEventKind
from kiyooo.diff.engine import diff_scan
from tests.graph.fakes import (
    FakeAssetRepository,
    FakeAssetSnapshotRepository,
    FakeChangeEventRepository,
)


def _asset(asset_type: AssetType, value: str) -> Asset:
    now = datetime.now(UTC)
    return Asset(
        id=uuid.uuid4(),
        type=asset_type,
        value=value,
        first_seen=now,
        last_seen=now,
        is_active=True,
        confidence_in_scope=1.0,
        scope_reason=None,
        attributes={},
    )


def _snapshot(
    scan_run_id: uuid.UUID, asset_id: uuid.UUID, state: dict[str, object]
) -> AssetSnapshot:
    import hashlib
    import json

    state_json = json.dumps(state, sort_keys=True, default=str)
    return AssetSnapshot(
        id=uuid.uuid4(),
        scan_run_id=scan_run_id,
        asset_id=asset_id,
        state_hash=hashlib.sha256(state_json.encode()).hexdigest(),
        state=state,
        observed_at=datetime.now(UTC),
    )


async def test_dod_scenario_end_to_end_two_events_zero_spurious() -> None:
    """Two consecutive scans of the same environment: one deliberately opened
    port, one deliberately removed auth redirect, and one asset that didn't
    change at all. Exactly two change_events, zero spurious.
    """
    previous_run_id = uuid.uuid4()
    current_run_id = uuid.uuid4()

    tcp_asset = _asset(AssetType.TCP_SERVICE, "93.184.216.34:8080")
    http_asset = _asset(AssetType.HTTP_SERVICE, "https://example.com")
    unchanged_asset = _asset(AssetType.CERT, "example.com:443")

    asset_repo = FakeAssetRepository()
    for asset in (tcp_asset, http_asset, unchanged_asset):
        asset_repo._by_id[asset.id] = asset

    snapshot_repo = FakeAssetSnapshotRepository()
    # Previous scan: tcp_asset didn't exist yet (no snapshot); http_asset
    # required auth; unchanged_asset had its cert state.
    snapshot_repo.snapshots.append(
        _snapshot(
            previous_run_id, http_asset.id, {"status_code": 200, "tech": [], "requires_auth": True}
        )
    )
    snapshot_repo.snapshots.append(
        _snapshot(
            previous_run_id,
            unchanged_asset.id,
            {"serial_number": "aaa", "subject_cn": "example.com"},
        )
    )
    # Current scan: tcp_asset now exists (port opened); http_asset no longer
    # requires auth; unchanged_asset's cert is identical.
    snapshot_repo.snapshots.append(
        _snapshot(current_run_id, tcp_asset.id, {"port": 8080, "protocol": "tcp"})
    )
    snapshot_repo.snapshots.append(
        _snapshot(
            current_run_id,
            http_asset.id,
            {"status_code": 200, "tech": [], "requires_auth": False},
        )
    )
    snapshot_repo.snapshots.append(
        _snapshot(
            current_run_id,
            unchanged_asset.id,
            {"serial_number": "aaa", "subject_cn": "example.com"},
        )
    )

    change_event_repo = FakeChangeEventRepository()
    events = await diff_scan(
        asset_repo,
        snapshot_repo,
        change_event_repo,
        scan_run_id=current_run_id,
        previous_scan_run_id=previous_run_id,
        assets=[tcp_asset, http_asset, unchanged_asset],
    )

    assert len(events) == 2
    kinds = {e.kind for e in events}
    assert kinds == {ChangeEventKind.PORT_OPENED, ChangeEventKind.AUTH_REMOVED}
    assert events == change_event_repo.events  # every event was actually persisted


async def test_identical_rescan_produces_zero_events() -> None:
    """Idempotency through the full diff_scan() pipeline, not just rules.py:
    re-running an unchanged scan must produce zero change_events.
    """
    previous_run_id = uuid.uuid4()
    current_run_id = uuid.uuid4()

    tcp_asset = _asset(AssetType.TCP_SERVICE, "93.184.216.34:8080")
    http_asset = _asset(AssetType.HTTP_SERVICE, "https://example.com")

    asset_repo = FakeAssetRepository()
    for asset in (tcp_asset, http_asset):
        asset_repo._by_id[asset.id] = asset

    same_tcp_state = {"port": 8080, "protocol": "tcp"}
    same_http_state = {"status_code": 200, "tech": ["nginx"], "requires_auth": False}

    snapshot_repo = FakeAssetSnapshotRepository()
    for run_id in (previous_run_id, current_run_id):
        snapshot_repo.snapshots.append(_snapshot(run_id, tcp_asset.id, dict(same_tcp_state)))
        snapshot_repo.snapshots.append(_snapshot(run_id, http_asset.id, dict(same_http_state)))

    change_event_repo = FakeChangeEventRepository()
    events = await diff_scan(
        asset_repo,
        snapshot_repo,
        change_event_repo,
        scan_run_id=current_run_id,
        previous_scan_run_id=previous_run_id,
        assets=[tcp_asset, http_asset],
    )

    assert events == []


async def test_no_previous_scan_run_means_everything_is_new() -> None:
    current_run_id = uuid.uuid4()
    asset = _asset(AssetType.SUBDOMAIN, "new.example.com")

    asset_repo = FakeAssetRepository()
    asset_repo._by_id[asset.id] = asset

    snapshot_repo = FakeAssetSnapshotRepository()
    snapshot_repo.snapshots.append(_snapshot(current_run_id, asset.id, {}))

    change_event_repo = FakeChangeEventRepository()
    events = await diff_scan(
        asset_repo,
        snapshot_repo,
        change_event_repo,
        scan_run_id=current_run_id,
        previous_scan_run_id=None,
        assets=[asset],
    )

    assert len(events) == 1
    assert events[0].kind == ChangeEventKind.ASSET_NEW


async def test_asset_missing_from_current_scan_is_asset_gone() -> None:
    previous_run_id = uuid.uuid4()
    current_run_id = uuid.uuid4()
    asset = _asset(AssetType.SUBDOMAIN, "gone.example.com")

    asset_repo = FakeAssetRepository()
    asset_repo._by_id[asset.id] = asset

    snapshot_repo = FakeAssetSnapshotRepository()
    snapshot_repo.snapshots.append(_snapshot(previous_run_id, asset.id, {}))
    # No snapshot for this asset in the current scan.

    change_event_repo = FakeChangeEventRepository()
    events = await diff_scan(
        asset_repo,
        snapshot_repo,
        change_event_repo,
        scan_run_id=current_run_id,
        previous_scan_run_id=previous_run_id,
        assets=[],  # asset wasn't touched this scan at all
    )

    assert len(events) == 1
    assert events[0].kind == ChangeEventKind.ASSET_GONE
