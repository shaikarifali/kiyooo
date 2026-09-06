from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kiyooo.config import ControlDefinition, PredicateBlock
from kiyooo.db.models import AssetType, Evidence, EvidenceKind
from kiyooo.detect.controls import detect_controls
from kiyooo.detect.predicates import PredicateContext
from tests.detect.fakes import FakeControlRepository
from tests.enrich.factories import make_asset


def _evidence(asset_id: uuid.UUID, header: dict[str, str]) -> list[Evidence]:
    now = datetime.now(UTC)
    return [
        Evidence(
            id=f"ev_{uuid.uuid4().hex[:8]}",
            scan_run_id=uuid.uuid4(),
            asset_id=asset_id,
            kind=EvidenceKind.HTTP_RESPONSE,
            source_tool="fixture",
            collected_at=now,
            content_ref=None,
            content_inline={"header": header},
            content_hash="fixture",
            size_bytes=None,
            redacted=False,
        )
    ]


def _sso_control() -> ControlDefinition:
    return ControlDefinition(
        id="sso_gateway",
        detect=PredicateBlock(any_of=[{"http_header_matches": {"x-auth-request-user": ".+"}}]),
        mitigates=["exposed-admin-panel"],
        action="suppress",
        requires_human_confirm_once=True,
    )


async def test_detect_controls_persists_matching_control() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://admin.example.com")
    evidence = _evidence(asset.id, {"x-auth-request-user": "alice"})
    control_repo = FakeControlRepository()
    ctx = PredicateContext()

    detected = await detect_controls([_sso_control()], asset, evidence, ctx, control_repo)

    assert len(detected) == 1
    assert detected[0].control_id == "sso_gateway"
    row = await control_repo.get_for_asset(asset.id, "sso_gateway")
    assert row is not None


async def test_detect_controls_no_match_persists_nothing() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://admin.example.com")
    evidence = _evidence(asset.id, {})
    control_repo = FakeControlRepository()
    ctx = PredicateContext()

    detected = await detect_controls([_sso_control()], asset, evidence, ctx, control_repo)

    assert detected == []
    assert await control_repo.get_for_asset(asset.id, "sso_gateway") is None


async def test_detect_controls_rerun_updates_not_duplicates() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://admin.example.com")
    evidence = _evidence(asset.id, {"x-auth-request-user": "alice"})
    control_repo = FakeControlRepository()
    ctx = PredicateContext()

    await detect_controls([_sso_control()], asset, evidence, ctx, control_repo)
    await detect_controls([_sso_control()], asset, evidence, ctx, control_repo)

    rows = await control_repo.list_for_asset(asset.id)
    assert len(rows) == 1
