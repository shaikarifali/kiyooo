from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kiyooo.db.models import AssetType, Evidence, EvidenceKind
from kiyooo.enrich.tech import apply_tech, merge_tech
from tests.enrich.factories import make_asset


def _evidence(kind: EvidenceKind, content_inline: dict[str, object] | None) -> Evidence:
    now = datetime.now(UTC)
    return Evidence(
        id=f"ev_test_{uuid.uuid4().hex[:8]}",
        scan_run_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        kind=kind,
        source_tool="httpx",
        collected_at=now,
        content_ref=None,
        content_inline=content_inline,
        content_hash="deadbeef",
        size_bytes=None,
        redacted=False,
    )


def test_merge_tech_collects_and_sorts_tech_from_http_evidence() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "api.example.com")
    evidence = [
        _evidence(EvidenceKind.HTTP_RESPONSE, {"tech": ["nginx", "React"]}),
        _evidence(EvidenceKind.HTTP_RESPONSE, {"tech": ["Ubuntu"]}),
    ]
    assert merge_tech(asset, evidence) == ["React", "Ubuntu", "nginx"]


def test_merge_tech_ignores_non_http_response_evidence() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "api.example.com")
    evidence = [_evidence(EvidenceKind.TLS_CERT, {"tech": ["nginx"]})]
    assert merge_tech(asset, evidence) == []


def test_merge_tech_preserves_existing_tech_not_reobserved() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "api.example.com")
    asset.attributes = {"tech": ["OldTech"]}
    evidence = [_evidence(EvidenceKind.HTTP_RESPONSE, {"tech": ["nginx"]})]
    assert merge_tech(asset, evidence) == ["OldTech", "nginx"]


def test_merge_tech_handles_missing_or_non_list_tech_field() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "api.example.com")
    evidence = [
        _evidence(EvidenceKind.HTTP_RESPONSE, {}),
        _evidence(EvidenceKind.HTTP_RESPONSE, None),
        _evidence(EvidenceKind.HTTP_RESPONSE, {"tech": "not-a-list"}),
    ]
    assert merge_tech(asset, evidence) == []


def test_apply_tech_reassigns_asset_attributes_without_losing_other_keys() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "api.example.com")
    asset.attributes = {"other_key": "keep-me"}
    evidence = [_evidence(EvidenceKind.HTTP_RESPONSE, {"tech": ["nginx"]})]

    apply_tech(asset, evidence)

    assert asset.attributes["other_key"] == "keep-me"
    assert asset.attributes["tech"] == ["nginx"]
