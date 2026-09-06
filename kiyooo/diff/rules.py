"""Per-kind change-event detection.

Given a `before`/`after` state pair for one asset (either can be `None` — no
snapshot in that scan), `detect()` returns the single most specific
`ChangeEventKind` that applies, or `None` if nothing interesting changed.
`diff/engine.py` calls this once per asset that appears in either of the two
scans being compared.

Two of the design's nine named kinds are not implemented here:

`DNS_CHANGED` (a hostname's resolved-IP set changed) and `TAKEOVER_RISK` (a
hostname stopped resolving to anything after previously resolving to
something) are both edge-set comparisons — "which `RESOLVES_TO` edges does
this hostname have now vs. last scan" — and `asset_edge` has no
`scan_run_id` column (the design's schema versions `asset_snapshot` per scan,
but not edges), so "the edge set as of scan N" isn't a query this schema can
answer precisely yet. Approximating it from `first_seen`/`last_seen`
timestamps would be unreliable enough to risk the DoD's own idempotency
requirement, so this is a documented gap, not a best-effort guess. Revisit if
edges ever get scan-scoped history.
"""

from __future__ import annotations

from kiyooo.db.models import AssetType, ChangeEventKind

Snapshot = dict[str, object] | None


def detect(asset_type: AssetType, before: Snapshot, after: Snapshot) -> ChangeEventKind | None:
    if before is None and after is None:
        return None
    if before is None:
        return _new_kind(asset_type)
    if after is None:
        return _gone_kind(asset_type)
    return _changed_kind(asset_type, before, after)


def _new_kind(asset_type: AssetType) -> ChangeEventKind:
    if asset_type == AssetType.TCP_SERVICE:
        return ChangeEventKind.PORT_OPENED
    return ChangeEventKind.ASSET_NEW


def _gone_kind(asset_type: AssetType) -> ChangeEventKind:
    if asset_type == AssetType.TCP_SERVICE:
        return ChangeEventKind.PORT_CLOSED
    return ChangeEventKind.ASSET_GONE


def _changed_kind(
    asset_type: AssetType, before: dict[str, object], after: dict[str, object]
) -> ChangeEventKind | None:
    if before == after:
        return None

    if asset_type == AssetType.CERT:
        if before.get("serial_number") != after.get("serial_number"):
            return ChangeEventKind.CERT_CHANGED
        return None

    if asset_type == AssetType.HTTP_SERVICE:
        # Priority order matters when more than one condition fires at once:
        # a status code moving out of the 401/403 range is the strongest
        # signal, then an auth requirement disappearing, then everything else.
        if before.get("status_code") in (401, 403) and after.get("status_code") == 200:
            return ChangeEventKind.WENT_PUBLIC
        if before.get("requires_auth") is True and after.get("requires_auth") is False:
            return ChangeEventKind.AUTH_REMOVED
        if before.get("tech") != after.get("tech"):
            return ChangeEventKind.TECH_CHANGED
        return None

    return None
