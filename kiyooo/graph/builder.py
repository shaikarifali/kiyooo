"""Idempotent Asset upserts and is_active decay.

`upsert_asset` is the one place raw tool output becomes an `Asset` row.
Stage 1's `EvidenceWriter` calls this instead of `AssetRepository.get_or_create`
directly, so every asset value is canonicalized before identity is resolved —
not just the ones Stage 2's own code happens to touch.
"""

from __future__ import annotations

from kiyooo.db.models import Asset, AssetType
from kiyooo.db.repo.asset import AssetRepository
from kiyooo.db.repo.scan_run import ScanRunRepository
from kiyooo.normalize.asset_identity import canonicalize

DEFAULT_DECAY_SCAN_THRESHOLD = 3


async def upsert_asset(
    asset_repo: AssetRepository,
    asset_type: AssetType,
    raw_value: str,
    *,
    confidence_in_scope: float,
) -> Asset:
    canonical_value = canonicalize(asset_type, raw_value)
    return await asset_repo.get_or_create(
        asset_type, canonical_value, confidence_in_scope=confidence_in_scope
    )


async def decay_inactive_assets(
    asset_repo: AssetRepository,
    scan_run_repo: ScanRunRepository,
    *,
    scan_threshold: int = DEFAULT_DECAY_SCAN_THRESHOLD,
) -> list[Asset]:
    """Mark `is_active = False` on assets not seen in `scan_threshold`
    consecutive completed scans. Never deletes a row — the design doc is explicit
    that attrition is a state change, not a removal: an asset's `asset_edge`/
    `evidence` history stays queryable after it decays, and `AssetRepository.
    get_or_create` reactivates it automatically if it's ever seen again.
    """
    recent_runs = await scan_run_repo.recent_completed(scan_threshold)
    if len(recent_runs) < scan_threshold:
        return []  # not enough scan history yet to call anything "unseen"

    cutoff = recent_runs[-1].started_at
    stale = await asset_repo.list_active_last_seen_before(cutoff)
    await asset_repo.mark_inactive(stale)
    return stale
