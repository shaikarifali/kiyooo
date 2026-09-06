"""Small object-construction helpers shared across enrich tests."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kiyooo.db.models import Asset, AssetType


def make_asset(asset_type: AssetType, value: str) -> Asset:
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
