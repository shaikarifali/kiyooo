from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kiyooo.db.models import AssetType, Evidence, EvidenceKind
from kiyooo.graph.snapshot import build_snapshots
from tests.graph.fakes import FakeAssetSnapshotRepository, FakeEvidenceRepository


def _asset(asset_type: AssetType, value: str):
    from kiyooo.db.models import Asset

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


def _evidence(
    scan_run_id: uuid.UUID, asset_id: uuid.UUID, kind: EvidenceKind, content: dict[str, object]
) -> Evidence:
    return Evidence(
        id=f"ev_{scan_run_id}_{uuid.uuid4().hex[:6]}",
        scan_run_id=scan_run_id,
        asset_id=asset_id,
        kind=kind,
        source_tool="test",
        collected_at=datetime.now(UTC),
        content_ref=None,
        content_inline=content,
        content_hash="x",
        size_bytes=len(str(content)),
        redacted=False,
    )


async def test_tcp_service_state_captures_port_and_protocol() -> None:
    scan_run_id = uuid.uuid4()
    asset = _asset(AssetType.TCP_SERVICE, "93.184.216.34:8080")
    evidence_repo = FakeEvidenceRepository()
    evidence_repo.seed(
        [
            _evidence(
                scan_run_id,
                asset.id,
                EvidenceKind.PORT_BANNER,
                {"port": 8080, "protocol": "tcp", "host": "93.184.216.34"},
            )
        ]
    )
    snapshot_repo = FakeAssetSnapshotRepository()

    snapshots = await build_snapshots(
        snapshot_repo, evidence_repo, scan_run_id=scan_run_id, assets=[asset]
    )

    assert len(snapshots) == 1
    assert snapshots[0].state == {"port": 8080, "protocol": "tcp"}


async def test_http_service_state_derives_requires_auth_from_status_code() -> None:
    scan_run_id = uuid.uuid4()
    asset = _asset(AssetType.HTTP_SERVICE, "https://example.com")
    evidence_repo = FakeEvidenceRepository()
    evidence_repo.seed(
        [
            _evidence(
                scan_run_id,
                asset.id,
                EvidenceKind.HTTP_RESPONSE,
                {"status_code": 403, "title": "Forbidden", "tech": ["nginx"]},
            )
        ]
    )
    snapshot_repo = FakeAssetSnapshotRepository()

    snapshots = await build_snapshots(
        snapshot_repo, evidence_repo, scan_run_id=scan_run_id, assets=[asset]
    )

    assert snapshots[0].state["requires_auth"] is True
    assert snapshots[0].state["status_code"] == 403


async def test_http_service_state_derives_requires_auth_from_login_title() -> None:
    scan_run_id = uuid.uuid4()
    asset = _asset(AssetType.HTTP_SERVICE, "https://example.com")
    evidence_repo = FakeEvidenceRepository()
    evidence_repo.seed(
        [
            _evidence(
                scan_run_id,
                asset.id,
                EvidenceKind.HTTP_RESPONSE,
                {"status_code": 200, "title": "Please Sign In", "tech": []},
            )
        ]
    )
    snapshot_repo = FakeAssetSnapshotRepository()

    snapshots = await build_snapshots(
        snapshot_repo, evidence_repo, scan_run_id=scan_run_id, assets=[asset]
    )

    assert snapshots[0].state["requires_auth"] is True


async def test_state_hash_is_deterministic_across_key_order() -> None:
    """The DoD's idempotency requirement depends on this: two evidence dicts
    with the same fields in a different order must hash identically.
    """
    scan_run_id_a = uuid.uuid4()
    scan_run_id_b = uuid.uuid4()
    asset = _asset(AssetType.CERT, "example.com:443")

    evidence_repo_a = FakeEvidenceRepository()
    evidence_repo_a.seed(
        [
            _evidence(
                scan_run_id_a,
                asset.id,
                EvidenceKind.TLS_CERT,
                {"serial_number": "aaa", "subject_cn": "example.com", "issuer_cn": "R3"},
            )
        ]
    )
    evidence_repo_b = FakeEvidenceRepository()
    evidence_repo_b.seed(
        [
            _evidence(
                scan_run_id_b,
                asset.id,
                EvidenceKind.TLS_CERT,
                {"issuer_cn": "R3", "serial_number": "aaa", "subject_cn": "example.com"},
            )
        ]
    )

    snap_a = await build_snapshots(
        FakeAssetSnapshotRepository(), evidence_repo_a, scan_run_id=scan_run_id_a, assets=[asset]
    )
    snap_b = await build_snapshots(
        FakeAssetSnapshotRepository(), evidence_repo_b, scan_run_id=scan_run_id_b, assets=[asset]
    )

    assert snap_a[0].state_hash == snap_b[0].state_hash


async def test_asset_type_without_a_state_rule_gets_empty_state() -> None:
    scan_run_id = uuid.uuid4()
    asset = _asset(AssetType.REPO, "acme/some-repo")
    evidence_repo = FakeEvidenceRepository()
    snapshot_repo = FakeAssetSnapshotRepository()

    snapshots = await build_snapshots(
        snapshot_repo, evidence_repo, scan_run_id=scan_run_id, assets=[asset]
    )

    assert snapshots[0].state == {}
