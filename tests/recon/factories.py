"""Small object-construction helpers shared across recon tests."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kiyooo.config import ScopeConfig
from kiyooo.db.models import (
    Asset,
    AssetType,
    Exclusion,
    ExclusionSource,
    ScopeAction,
    Seed,
    SeedKind,
)


def make_scope(**overrides: object) -> ScopeConfig:
    defaults: dict[str, object] = {
        "org_name": "testcorp",
        "relationship": "first_party",
        "active_scanning_enabled": False,
        "attestation": False,
        "domains": ["example.com"],
        "wildcards": ["*.example.com"],
        "cidrs": ["203.0.113.0/24"],
        "asns": [64500],
        "cloud_accounts": ["prod-account"],
        "exclude": ["excluded.example.com"],
    }
    defaults.update(overrides)
    return ScopeConfig.model_validate(defaults)


def make_asset(type_: AssetType, value: str) -> Asset:
    now = datetime.now(UTC)
    return Asset(
        id=uuid.uuid4(),
        type=type_,
        value=value,
        first_seen=now,
        last_seen=now,
        is_active=True,
        confidence_in_scope=1.0,
        scope_reason=None,
        attributes={},
    )


def make_seed(
    *,
    org_id: uuid.UUID | None = None,
    kind: SeedKind = SeedKind.APEX_DOMAIN,
    value: str = "example.com",
    scope_action: ScopeAction = ScopeAction.INCLUDE,
    active_scan_allowed: bool | None = None,
    verified: bool = False,
    disabled_at: datetime | None = None,
) -> Seed:
    now = datetime.now(UTC)
    return Seed(
        id=uuid.uuid4(),
        org_id=org_id or uuid.uuid4(),
        kind=kind,
        value=value,
        scope_action=scope_action,
        active_scan_allowed=active_scan_allowed,
        verified=verified,
        note=None,
        added_by="tester@example.com",
        added_at=now,
        disabled_at=disabled_at,
    )


def make_exclusion(
    *,
    org_id: uuid.UUID | None = None,
    kind: SeedKind = SeedKind.APEX_DOMAIN,
    value: str = "excluded.example.com",
    reason: str = "test exclusion",
    source: ExclusionSource = ExclusionSource.USER,
) -> Exclusion:
    return Exclusion(
        id=uuid.uuid4(),
        org_id=org_id,
        kind=kind,
        value=value,
        reason=reason,
        source=source,
        created_at=datetime.now(UTC),
    )
