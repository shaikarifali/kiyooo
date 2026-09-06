from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kiyooo.db.models import AssetType, Evidence, EvidenceKind
from kiyooo.enrich.ai_tech import apply_ai_tech, merge_ai_tech
from tests.enrich.factories import make_asset


def _evidence(kind: EvidenceKind, content_inline: dict[str, object] | None) -> Evidence:
    now = datetime.now(UTC)
    return Evidence(
        id=f"ev_test_{uuid.uuid4().hex[:8]}",
        scan_run_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        kind=kind,
        source_tool="naabu",
        collected_at=now,
        content_ref=None,
        content_inline=content_inline,
        content_hash="deadbeef",
        size_bytes=None,
        redacted=False,
    )


def test_merge_ai_tech_matches_by_port() -> None:
    asset = make_asset(AssetType.TCP_SERVICE, "10.0.0.5:11434")
    evidence = [_evidence(EvidenceKind.PORT_BANNER, {"port": 11434})]
    assert merge_ai_tech(asset, evidence) == ["ollama"]


def test_merge_ai_tech_no_signal_is_empty() -> None:
    asset = make_asset(AssetType.TCP_SERVICE, "10.0.0.5:443")
    evidence = [_evidence(EvidenceKind.PORT_BANNER, {"port": 443})]
    assert merge_ai_tech(asset, evidence) == []


def test_merge_ai_tech_preserves_existing_not_reobserved() -> None:
    asset = make_asset(AssetType.TCP_SERVICE, "10.0.0.5:11434")
    asset.attributes = {"ai_tech": ["chroma"]}
    evidence = [_evidence(EvidenceKind.PORT_BANNER, {"port": 11434})]
    assert merge_ai_tech(asset, evidence) == ["chroma", "ollama"]


def test_apply_ai_tech_reassigns_attributes_without_losing_other_keys() -> None:
    asset = make_asset(AssetType.TCP_SERVICE, "10.0.0.5:11434")
    asset.attributes = {"tech": ["nginx"]}
    evidence = [_evidence(EvidenceKind.PORT_BANNER, {"port": 11434})]

    apply_ai_tech(asset, evidence)

    assert asset.attributes["tech"] == ["nginx"]
    assert asset.attributes["ai_tech"] == ["ollama"]
