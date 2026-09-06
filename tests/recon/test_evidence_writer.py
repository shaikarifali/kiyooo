"""Direct unit test of `EvidenceWriter._write_one` (via `write_many`) —
`tests/recon/test_orchestrator.py` exercises the stage DAG against a fake
writer, so the real writer's redact-before-hash behavior (invariant #7)
has no other coverage.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kiyooo.db.models import AssetType, EvidenceKind
from kiyooo.recon.base import ParsedEvidence
from kiyooo.recon.orchestrator import EvidenceWriter
from tests.graph.fakes import FakeAssetRepository, FakeEvidenceRepository


class _NoopAssetEdgeRepo:
    async def add(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("no edge hints expected for source_tool='fixture'")


async def test_evidence_writer_redacts_secret_before_persisting() -> None:
    evidence_repo = FakeEvidenceRepository()
    asset_repo = FakeAssetRepository()
    writer = EvidenceWriter(
        evidence_repo=evidence_repo,  # type: ignore[arg-type]
        asset_repo=asset_repo,  # type: ignore[arg-type]
        asset_edge_repo=_NoopAssetEdgeRepo(),  # type: ignore[arg-type]
        minio_client=None,  # type: ignore[arg-type]
        bucket="test-bucket",
        scan_run_id=uuid.uuid4(),
    )

    parsed = ParsedEvidence(
        kind=EvidenceKind.HTTP_RESPONSE,
        asset_type=AssetType.HTTP_SERVICE,
        asset_value="app.example.com",
        content={"header": {"Authorization": "Bearer ghp_" + "a" * 36}, "status_code": 200},
        collected_at=datetime.now(UTC),
    )

    await writer.write_many([parsed], source_tool="fixture")

    stored = await evidence_repo.for_scan_run(writer._scan_run_id)  # noqa: SLF001
    assert len(stored) == 1
    evidence = stored[0]
    assert evidence.redacted is True
    assert "ghp_" not in str(evidence.content_inline)
    assert evidence.content_inline is not None
    assert evidence.content_inline["status_code"] == 200
    redacted_secrets = evidence.content_inline["_redacted_secrets"]
    assert redacted_secrets[0]["secret_type"] == "github_token"


async def test_evidence_writer_leaves_clean_content_unredacted() -> None:
    evidence_repo = FakeEvidenceRepository()
    asset_repo = FakeAssetRepository()
    writer = EvidenceWriter(
        evidence_repo=evidence_repo,  # type: ignore[arg-type]
        asset_repo=asset_repo,  # type: ignore[arg-type]
        asset_edge_repo=_NoopAssetEdgeRepo(),  # type: ignore[arg-type]
        minio_client=None,  # type: ignore[arg-type]
        bucket="test-bucket",
        scan_run_id=uuid.uuid4(),
    )

    parsed = ParsedEvidence(
        kind=EvidenceKind.PORT_BANNER,
        asset_type=AssetType.TCP_SERVICE,
        asset_value="10.0.0.5:3306",
        content={"port": 3306, "protocol": "tcp"},
        collected_at=datetime.now(UTC),
    )

    await writer.write_many([parsed], source_tool="fixture")

    stored = await evidence_repo.for_scan_run(writer._scan_run_id)  # noqa: SLF001
    assert stored[0].redacted is False
    assert "_redacted_secrets" not in (stored[0].content_inline or {})
