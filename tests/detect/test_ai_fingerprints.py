from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kiyooo.db.models import Evidence, EvidenceKind
from kiyooo.detect.ai_fingerprints import load_catalog, match_signatures


def _evidence(kind: EvidenceKind, content: dict[str, object]) -> Evidence:
    return Evidence(
        id=f"ev_{uuid.uuid4().hex[:8]}",
        scan_run_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        kind=kind,
        source_tool="fixture",
        collected_at=datetime.now(UTC),
        content_ref=None,
        content_inline=content,
        content_hash="fixture",
        size_bytes=None,
        redacted=False,
    )


def test_load_catalog_has_entries() -> None:
    catalog = load_catalog()
    assert len(catalog) > 10
    ids = {sig.id for sig in catalog}
    assert "ollama" in ids
    assert "chroma" in ids
    assert "jupyter" in ids


def test_match_by_port() -> None:
    evidence = [_evidence(EvidenceKind.PORT_BANNER, {"port": 11434})]
    matched = match_signatures(evidence)
    assert "ollama" in matched


def test_match_by_body_pattern() -> None:
    evidence = [_evidence(EvidenceKind.HTTP_RESPONSE, {"body": "Ollama is running"})]
    matched = match_signatures(evidence)
    assert "ollama" in matched


def test_no_match_for_unrelated_evidence() -> None:
    evidence = [_evidence(EvidenceKind.PORT_BANNER, {"port": 443})]
    matched = match_signatures(evidence)
    assert matched == []


def test_multiple_signatures_deduplicated_and_sorted() -> None:
    evidence = [
        _evidence(EvidenceKind.PORT_BANNER, {"port": 11434}),
        _evidence(EvidenceKind.PORT_BANNER, {"port": 11434}),
        _evidence(EvidenceKind.PORT_BANNER, {"port": 8888}),
    ]
    matched = match_signatures(evidence)
    assert matched == sorted(matched)
    assert matched.count("ollama") == 1


def test_ignores_evidence_kinds_that_are_not_banner_or_response() -> None:
    evidence = [_evidence(EvidenceKind.TLS_CERT, {"port": 11434})]
    matched = match_signatures(evidence)
    assert matched == []


def test_mcp_signature_matches_jsonrpc_body() -> None:
    evidence = [_evidence(EvidenceKind.HTTP_RESPONSE, {"body": '{"jsonrpc": "2.0"}'})]
    matched = match_signatures(evidence)
    assert "mcp_http" in matched
