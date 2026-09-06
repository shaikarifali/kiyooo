"""Edge-derivation tests. Reuses Stage 1's recon fixtures (tests/fixtures/recon/)
since derive_edges() reads the same ParsedEvidence.content that Stage 1's
adapter parsers already produce — see kiyooo/normalize/parsers/__init__.py's
docstring for why this is evidence-driven rather than adapter-driven.
"""

from __future__ import annotations

from datetime import UTC, datetime

from kiyooo.db.models import AssetEdgeRelation, AssetType, EvidenceKind
from kiyooo.normalize.parsers import derive_edges
from kiyooo.recon.base import ParsedEvidence

_NOW = datetime.now(UTC)


def _evidence(
    asset_type: AssetType, asset_value: str, content: dict[str, object]
) -> ParsedEvidence:
    return ParsedEvidence(
        kind=EvidenceKind.DNS_RECORD,
        asset_type=asset_type,
        asset_value=asset_value,
        content=content,
        collected_at=_NOW,
    )


def test_dnsx_derives_host_resolves_to_ip() -> None:
    item = _evidence(
        AssetType.IP, "93.184.216.34", {"host": "www.example.com", "a": ["93.184.216.34"]}
    )
    hints = derive_edges("dnsx", item)
    assert len(hints) == 1
    hint = hints[0]
    assert hint.relation == AssetEdgeRelation.RESOLVES_TO
    assert hint.related_asset_value == "www.example.com"
    assert hint.own_is_src is False  # host --RESOLVES_TO--> ip (item's own asset)


def test_dnsx_with_missing_host_produces_no_edges() -> None:
    item = _evidence(AssetType.IP, "93.184.216.34", {"a": ["93.184.216.34"]})
    assert derive_edges("dnsx", item) == []


def test_tlsx_derives_cert_issued_for_host() -> None:
    item = _evidence(
        AssetType.CERT,
        "www.example.com:443",
        {"host": "www.example.com", "subject_cn": "www.example.com"},
    )
    hints = derive_edges("tlsx", item)
    assert len(hints) == 1
    hint = hints[0]
    assert hint.relation == AssetEdgeRelation.ISSUED_FOR
    assert hint.related_asset_value == "www.example.com"
    assert hint.own_is_src is True  # cert (item's own asset) --ISSUED_FOR--> host


def test_naabu_derives_tcp_service_hosted_on_host() -> None:
    item = _evidence(
        AssetType.TCP_SERVICE, "93.184.216.34:443", {"host": "93.184.216.34", "port": 443}
    )
    hints = derive_edges("naabu", item)
    assert len(hints) == 1
    hint = hints[0]
    assert hint.relation == AssetEdgeRelation.HOSTED_ON
    assert hint.related_asset_value == "93.184.216.34"
    assert hint.own_is_src is True


def test_naabu_falls_back_to_ip_field_when_host_absent() -> None:
    item = _evidence(AssetType.TCP_SERVICE, "93.184.216.34:443", {"ip": "93.184.216.34"})
    hints = derive_edges("naabu", item)
    assert hints[0].related_asset_value == "93.184.216.34"


def test_httpx_derives_host_serves_http_service() -> None:
    item = _evidence(
        AssetType.HTTP_SERVICE,
        "https://www.example.com",
        {"host": "www.example.com", "status_code": 200},
    )
    hints = derive_edges("httpx", item)
    assert len(hints) == 1
    hint = hints[0]
    assert hint.relation == AssetEdgeRelation.SERVES
    assert hint.related_asset_value == "www.example.com"
    assert hint.own_is_src is False  # host --SERVES--> http_service (item's own asset)


def test_related_value_is_canonicalized() -> None:
    item = _evidence(AssetType.IP, "93.184.216.34", {"host": "WWW.Example.COM."})
    hint = derive_edges("dnsx", item)[0]
    assert hint.related_asset_value == "www.example.com"


def test_related_value_detects_ip_vs_hostname() -> None:
    # naabu's "host" field is sometimes literally an IP, not a hostname —
    # resolve_related_value must pick IP canonicalization in that case, not
    # try (and harmlessly fail) IDNA-encoding a dotted-quad.
    item = _evidence(AssetType.TCP_SERVICE, "93.184.216.34:443", {"host": "93.184.216.34"})
    hint = derive_edges("naabu", item)[0]
    assert hint.related_asset_value == "93.184.216.34"


def test_unknown_source_tool_produces_no_edges() -> None:
    item = _evidence(AssetType.SUBDOMAIN, "sub.example.com", {"host": "sub.example.com"})
    assert derive_edges("some-tool-with-no-parser", item) == []


def test_katana_has_no_edge_parser_by_design() -> None:
    """Documented gap, not an oversight — see normalize/parsers/__init__.py."""
    item = _evidence(
        AssetType.URL,
        "https://www.example.com/about",
        {"request": {"endpoint": "https://www.example.com/about"}},
    )
    assert derive_edges("katana", item) == []
