"""snapshot(N-1) vs snapshot(N) -> `change_event` rows.

Compares every asset that has a snapshot in either the current scan or the
previous one, and persists a `ChangeEvent` for every kind `diff.rules.detect`
returns. An asset present in both gets its `state` fields compared; present
only in the current scan is `ASSET_NEW`/`PORT_OPENED`; present only in the
previous scan is `ASSET_GONE`/`PORT_CLOSED` (see `diff/rules.py`).

Idempotency (the DoD's other hard requirement) falls out of this directly:
re-running an unchanged scan produces byte-identical `state` dicts (see
`graph/snapshot.py`'s curation), so `before == after` for every asset and
`detect()` returns `None` every time — zero events, not almost zero.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from kiyooo.db.models import Asset, ChangeEvent, ChangeEventKind, Severity
from kiyooo.db.repo.asset import AssetRepository
from kiyooo.db.repo.asset_snapshot import AssetSnapshotRepository
from kiyooo.db.repo.change_event import ChangeEventRepository
from kiyooo.diff.rules import detect

_SEVERITY_HINTS: dict[ChangeEventKind, Severity] = {
    ChangeEventKind.PORT_OPENED: Severity.MEDIUM,
    ChangeEventKind.PORT_CLOSED: Severity.INFO,
    ChangeEventKind.AUTH_REMOVED: Severity.HIGH,
    ChangeEventKind.WENT_PUBLIC: Severity.HIGH,
    ChangeEventKind.CERT_CHANGED: Severity.LOW,
    ChangeEventKind.TECH_CHANGED: Severity.INFO,
    ChangeEventKind.ASSET_NEW: Severity.INFO,
    ChangeEventKind.ASSET_GONE: Severity.INFO,
}


async def diff_scan(
    asset_repo: AssetRepository,
    asset_snapshot_repo: AssetSnapshotRepository,
    change_event_repo: ChangeEventRepository,
    *,
    scan_run_id: UUID,
    previous_scan_run_id: UUID | None,
    assets: list[Asset],
) -> list[ChangeEvent]:
    current_snapshots = {s.asset_id: s for s in await asset_snapshot_repo.for_scan_run(scan_run_id)}
    previous_snapshots = (
        {s.asset_id: s for s in await asset_snapshot_repo.for_scan_run(previous_scan_run_id)}
        if previous_scan_run_id is not None
        else {}
    )

    asset_by_id = {a.id: a for a in assets}
    now = datetime.now(UTC)
    events: list[ChangeEvent] = []

    for asset_id in set(current_snapshots) | set(previous_snapshots):
        asset = asset_by_id.get(asset_id) or await asset_repo.get(asset_id)
        if asset is None:
            continue  # asset row itself is gone; nothing to attach an event to

        before_snap = previous_snapshots.get(asset_id)
        after_snap = current_snapshots.get(asset_id)
        kind = detect(
            asset.type,
            before_snap.state if before_snap else None,
            after_snap.state if after_snap else None,
        )
        if kind is None:
            continue

        event = ChangeEvent(
            scan_run_id=scan_run_id,
            asset_id=asset_id,
            kind=kind,
            before=before_snap.state if before_snap else None,
            after=after_snap.state if after_snap else None,
            severity_hint=_SEVERITY_HINTS.get(kind, Severity.INFO),
            occurred_at=now,
        )
        events.append(await change_event_repo.add(event))

    return events
