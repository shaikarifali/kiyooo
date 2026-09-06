from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from kiyooo.db.models import AssetType, Control, Evidence, EvidenceKind
from kiyooo.detect import predicates as p
from kiyooo.enrich.epss import EpssScore
from kiyooo.enrich.kev import KevCatalog, KevEntry
from tests.enrich.factories import make_asset


def _evidence(
    kind: EvidenceKind,
    content: dict[str, object],
    asset_id: uuid.UUID | None = None,
    *,
    injection_suspected: bool = False,
) -> Evidence:
    now = datetime.now(UTC)
    return Evidence(
        id=f"ev_{uuid.uuid4().hex[:8]}",
        scan_run_id=uuid.uuid4(),
        asset_id=asset_id or uuid.uuid4(),
        kind=kind,
        source_tool="fixture",
        collected_at=now,
        content_ref=None,
        content_inline=content,
        content_hash="fixture",
        size_bytes=None,
        redacted=False,
        injection_suspected=injection_suspected,
    )


def _ctx(**kwargs: object) -> p.PredicateContext:
    return p.PredicateContext(**kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# hostname_matches
# --------------------------------------------------------------------------- #


def test_hostname_matches_subdomain() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "staging.example.com")
    result = p.hostname_matches(asset, [], _ctx(), "(?i)^staging\\.")
    assert result.matched is True


def test_hostname_matches_no_match() -> None:
    asset = make_asset(AssetType.SUBDOMAIN, "app.example.com")
    result = p.hostname_matches(asset, [], _ctx(), "(?i)^staging\\.")
    assert result.matched is False


def test_hostname_matches_extracts_host_from_url() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://admin.example.com:8443/path")
    result = p.hostname_matches(asset, [], _ctx(), "(?i)^admin\\.")
    assert result.matched is True


# --------------------------------------------------------------------------- #
# http_header_matches
# --------------------------------------------------------------------------- #


def test_http_header_matches() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _evidence(EvidenceKind.HTTP_RESPONSE, {"header": {"X-Environment": "staging"}}, asset.id)
    result = p.http_header_matches(asset, [ev], _ctx(), {"X-Environment": "(?i)staging"})
    assert result.matched is True
    assert result.evidence_ids == [ev.id]


def test_http_header_matches_no_match() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _evidence(EvidenceKind.HTTP_RESPONSE, {"header": {"X-Environment": "prod"}}, asset.id)
    result = p.http_header_matches(asset, [ev], _ctx(), {"X-Environment": "(?i)staging"})
    assert result.matched is False


# --------------------------------------------------------------------------- #
# http_body_matches / body_entropy_above / redirect_chain_matches
# --------------------------------------------------------------------------- #


def test_http_body_matches() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _evidence(EvidenceKind.HTTP_RESPONSE, {"body": "Werkzeug Debugger active"}, asset.id)
    result = p.http_body_matches(asset, [ev], _ctx(), "(?i)werkzeug debugger")
    assert result.matched is True


def test_http_body_matches_no_match() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _evidence(EvidenceKind.HTTP_RESPONSE, {"body": "Welcome"}, asset.id)
    result = p.http_body_matches(asset, [ev], _ctx(), "(?i)werkzeug debugger")
    assert result.matched is False


def test_body_entropy_above_high_entropy_body() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    body = "aK9fQ2mZ7xW4nR8pL1vC6tY3sJ0gH5dB8kM2wX9uV4rT7pS1nQ6zL3fD8jH2mA5cE9gI4kO7bN0"
    ev = _evidence(EvidenceKind.HTTP_RESPONSE, {"body": body}, asset.id)
    result = p.body_entropy_above(asset, [ev], _ctx(), 4.5)
    assert result.matched is True


def test_body_entropy_above_low_entropy_body() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _evidence(EvidenceKind.HTTP_RESPONSE, {"body": "a" * 200}, asset.id)
    result = p.body_entropy_above(asset, [ev], _ctx(), 4.5)
    assert result.matched is False


def test_redirect_chain_matches() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _evidence(
        EvidenceKind.HTTP_RESPONSE,
        {"chain": ["https://app.example.com", "https://login.microsoftonline.com/x"]},
        asset.id,
    )
    result = p.redirect_chain_matches(asset, [ev], _ctx(), "login\\.microsoftonline\\.com")
    assert result.matched is True


def test_redirect_chain_matches_no_match() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _evidence(EvidenceKind.HTTP_RESPONSE, {"chain": ["https://app.example.com"]}, asset.id)
    result = p.redirect_chain_matches(asset, [ev], _ctx(), "login\\.microsoftonline\\.com")
    assert result.matched is False


# --------------------------------------------------------------------------- #
# port_in / service_banner_matches / internet_reachable / responds_without_auth
# --------------------------------------------------------------------------- #


def test_port_in_match() -> None:
    asset = make_asset(AssetType.TCP_SERVICE, "10.0.0.5:3306")
    ev = _evidence(EvidenceKind.PORT_BANNER, {"port": 3306}, asset.id)
    result = p.port_in(asset, [ev], _ctx(), [3306, 5432])
    assert result.matched is True


def test_port_in_no_match() -> None:
    asset = make_asset(AssetType.TCP_SERVICE, "10.0.0.5:22")
    ev = _evidence(EvidenceKind.PORT_BANNER, {"port": 22}, asset.id)
    result = p.port_in(asset, [ev], _ctx(), [3306, 5432])
    assert result.matched is False


def test_service_banner_matches() -> None:
    asset = make_asset(AssetType.TCP_SERVICE, "10.0.0.5:3306")
    ev = _evidence(EvidenceKind.PORT_BANNER, {"banner": "5.7.31-MySQL Community Server"}, asset.id)
    result = p.service_banner_matches(asset, [ev], _ctx(), "(?i)mysql")
    assert result.matched is True


def test_service_banner_matches_no_match() -> None:
    asset = make_asset(AssetType.TCP_SERVICE, "10.0.0.5:22")
    ev = _evidence(EvidenceKind.PORT_BANNER, {"banner": "OpenSSH 8.9"}, asset.id)
    result = p.service_banner_matches(asset, [ev], _ctx(), "(?i)mysql")
    assert result.matched is False


def test_internet_reachable_true_with_evidence() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _evidence(EvidenceKind.HTTP_RESPONSE, {}, asset.id)
    result = p.internet_reachable(asset, [ev], _ctx(), True)
    assert result.matched is True


def test_internet_reachable_false_with_no_evidence() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    result = p.internet_reachable(asset, [], _ctx(), False)
    assert result.matched is True


def test_internet_reachable_true_but_no_evidence_is_no_match() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    result = p.internet_reachable(asset, [], _ctx(), True)
    assert result.matched is False


def test_responds_without_auth_true() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _evidence(EvidenceKind.HTTP_RESPONSE, {"status_code": 200, "title": "Dashboard"}, asset.id)
    result = p.responds_without_auth(asset, [ev], _ctx(), True)
    assert result.matched is True


def test_responds_without_auth_false_on_401() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _evidence(EvidenceKind.HTTP_RESPONSE, {"status_code": 401, "title": "Login"}, asset.id)
    result = p.responds_without_auth(asset, [ev], _ctx(), True)
    assert result.matched is False


# --------------------------------------------------------------------------- #
# TLS cert predicates
# --------------------------------------------------------------------------- #


def test_tls_cert_cn_matches() -> None:
    asset = make_asset(AssetType.CERT, "app.example.com:443")
    ev = _evidence(EvidenceKind.TLS_CERT, {"subject_cn": "*.dev.example.com"}, asset.id)
    result = p.tls_cert_cn_matches(asset, [ev], _ctx(), "\\*\\.dev\\.")
    assert result.matched is True


def test_tls_cert_cn_matches_no_match() -> None:
    asset = make_asset(AssetType.CERT, "app.example.com:443")
    ev = _evidence(EvidenceKind.TLS_CERT, {"subject_cn": "app.example.com"}, asset.id)
    result = p.tls_cert_cn_matches(asset, [ev], _ctx(), "\\*\\.dev\\.")
    assert result.matched is False


def test_tls_cert_expires_within_days_matches_soon_expiring() -> None:
    asset = make_asset(AssetType.CERT, "app.example.com:443")
    now = datetime.now(UTC)
    not_after = (now + timedelta(days=5)).isoformat().replace("+00:00", "Z")
    ev = _evidence(EvidenceKind.TLS_CERT, {"not_after": not_after, "serial_number": "S1"}, asset.id)
    result = p.tls_cert_expires_within_days(asset, [ev], _ctx(now=now), 14)
    assert result.matched is True
    assert result.discriminator == "S1"


def test_tls_cert_expires_within_days_no_match_far_future() -> None:
    asset = make_asset(AssetType.CERT, "app.example.com:443")
    now = datetime.now(UTC)
    not_after = (now + timedelta(days=200)).isoformat().replace("+00:00", "Z")
    ev = _evidence(EvidenceKind.TLS_CERT, {"not_after": not_after, "serial_number": "S1"}, asset.id)
    result = p.tls_cert_expires_within_days(asset, [ev], _ctx(now=now), 14)
    assert result.matched is False


def test_tls_handshake_requires_client_cert() -> None:
    asset = make_asset(AssetType.CERT, "app.example.com:443")
    ev = _evidence(EvidenceKind.TLS_CERT, {"requires_client_cert": True}, asset.id)
    result = p.tls_handshake_requires_client_cert(asset, [ev], _ctx(), True)
    assert result.matched is True


def test_tls_handshake_requires_client_cert_no_match() -> None:
    asset = make_asset(AssetType.CERT, "app.example.com:443")
    ev = _evidence(EvidenceKind.TLS_CERT, {"requires_client_cert": False}, asset.id)
    result = p.tls_handshake_requires_client_cert(asset, [ev], _ctx(), True)
    assert result.matched is False


# --------------------------------------------------------------------------- #
# cloud / ASN
# --------------------------------------------------------------------------- #


def test_resolved_ip_in_asn_match() -> None:
    asset = make_asset(AssetType.IP, "104.16.0.1")
    ev = _evidence(EvidenceKind.ASN_RECORD, {"asn": 13335}, asset.id)
    result = p.resolved_ip_in_asn(asset, [ev], _ctx(), [13335])
    assert result.matched is True


def test_resolved_ip_in_asn_no_match() -> None:
    asset = make_asset(AssetType.IP, "8.8.8.8")
    ev = _evidence(EvidenceKind.ASN_RECORD, {"asn": 15169}, asset.id)
    result = p.resolved_ip_in_asn(asset, [ev], _ctx(), [13335])
    assert result.matched is False


def test_cloud_tag_equals_match() -> None:
    asset = make_asset(AssetType.CLOUD_RESOURCE, "s3://acmecorp-reports")
    ev = _evidence(EvidenceKind.CLOUD_CONFIG, {"tags": {"public_access": "true"}}, asset.id)
    result = p.cloud_tag_equals(asset, [ev], _ctx(), {"public_access": "true"})
    assert result.matched is True


def test_cloud_tag_equals_no_match() -> None:
    asset = make_asset(AssetType.CLOUD_RESOURCE, "s3://acmecorp-private")
    ev = _evidence(EvidenceKind.CLOUD_CONFIG, {"tags": {"public_access": "false"}}, asset.id)
    result = p.cloud_tag_equals(asset, [ev], _ctx(), {"public_access": "true"})
    assert result.matched is False


# --------------------------------------------------------------------------- #
# has_control
# --------------------------------------------------------------------------- #


def test_has_control_match() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://admin.example.com")
    control = Control(
        id=uuid.uuid4(),
        asset_id=asset.id,
        control_id="sso_gateway",
        detected_by="rule",
        evidence_id="ev_1",
        detected_at=datetime.now(UTC),
    )
    result = p.has_control(asset, [], _ctx(detected_controls=[control]), "sso_gateway")
    assert result.matched is True
    assert result.evidence_ids == ["ev_1"]


def test_has_control_no_match_different_asset() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://admin.example.com")
    other_asset_id = uuid.uuid4()
    control = Control(
        id=uuid.uuid4(),
        asset_id=other_asset_id,
        control_id="sso_gateway",
        detected_by="rule",
        evidence_id=None,
        detected_at=datetime.now(UTC),
    )
    result = p.has_control(asset, [], _ctx(detected_controls=[control]), "sso_gateway")
    assert result.matched is False


# --------------------------------------------------------------------------- #
# cve_in_kev / epss_above
# --------------------------------------------------------------------------- #


def _nuclei_evidence(asset_id: uuid.UUID, cve_id: str) -> Evidence:
    return _evidence(
        EvidenceKind.NUCLEI_RESULT,
        {"template-id": cve_id.lower(), "info": {"classification": {"cve-id": [cve_id]}}},
        asset_id,
    )


def test_cve_in_kev_match() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _nuclei_evidence(asset.id, "CVE-2023-12345")
    catalog = KevCatalog(
        entries={
            "CVE-2023-12345": KevEntry(
                cve_id="CVE-2023-12345",
                vendor_project="Acme",
                product="Widget",
                vulnerability_name="RCE",
                date_added="2023-06-01",
                known_ransomware_use=True,
            )
        },
        catalog_version="1",
        date_released="2023-06-01",
    )
    result = p.cve_in_kev(asset, [ev], _ctx(kev_catalog=catalog), True)
    assert result.matched is True
    assert result.discriminator == "CVE-2023-12345"


def test_cve_in_kev_no_match_absent_from_catalog() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _nuclei_evidence(asset.id, "CVE-2024-00000")
    catalog = KevCatalog(entries={}, catalog_version="1", date_released="2023-06-01")
    result = p.cve_in_kev(asset, [ev], _ctx(kev_catalog=catalog), True)
    assert result.matched is False


def test_cve_in_kev_no_catalog_is_no_match() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _nuclei_evidence(asset.id, "CVE-2023-12345")
    result = p.cve_in_kev(asset, [ev], _ctx(kev_catalog=None), True)
    assert result.matched is False


def test_epss_above_match() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _nuclei_evidence(asset.id, "CVE-2023-12345")
    scores = {"CVE-2023-12345": EpssScore(cve_id="CVE-2023-12345", score=0.95, percentile=0.99)}
    result = p.epss_above(asset, [ev], _ctx(epss_scores=scores), 0.5)
    assert result.matched is True
    assert result.discriminator == "CVE-2023-12345"


def test_epss_above_no_match_below_threshold() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _nuclei_evidence(asset.id, "CVE-2023-12345")
    scores = {"CVE-2023-12345": EpssScore(cve_id="CVE-2023-12345", score=0.01, percentile=0.1)}
    result = p.epss_above(asset, [ev], _ctx(epss_scores=scores), 0.5)
    assert result.matched is False


# --------------------------------------------------------------------------- #
# evidence_injection_suspected — Stage 11b's mcp-tool-poisoning-risk
# --------------------------------------------------------------------------- #


def test_evidence_injection_suspected_match() -> None:
    asset = make_asset(AssetType.MCP_SERVER, "mcp.internal.example.com:3001")
    ev = _evidence(
        EvidenceKind.HTTP_RESPONSE,
        {"body": "hidden instructions"},
        asset.id,
        injection_suspected=True,
    )
    result = p.evidence_injection_suspected(asset, [ev], _ctx(), True)
    assert result.matched is True
    assert result.evidence_ids == [ev.id]


def test_evidence_injection_suspected_no_match_when_clean() -> None:
    asset = make_asset(AssetType.MCP_SERVER, "mcp.internal.example.com:3001")
    ev = _evidence(
        EvidenceKind.HTTP_RESPONSE, {"body": "clean manifest"}, asset.id, injection_suspected=False
    )
    result = p.evidence_injection_suspected(asset, [ev], _ctx(), True)
    assert result.matched is False


def test_evidence_injection_suspected_arg_false_matches_when_clean() -> None:
    asset = make_asset(AssetType.MCP_SERVER, "mcp.internal.example.com:3001")
    ev = _evidence(
        EvidenceKind.HTTP_RESPONSE, {"body": "clean manifest"}, asset.id, injection_suspected=False
    )
    result = p.evidence_injection_suspected(asset, [ev], _ctx(), False)
    assert result.matched is True


# --------------------------------------------------------------------------- #
# tls_protocol_version_in / nuclei_tags_include — Stage 12's demo-lab categories
# --------------------------------------------------------------------------- #


def test_tls_protocol_version_in_match() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://legacy.example.com")
    ev = _evidence(EvidenceKind.TLS_CERT, {"protocol_version": "TLSv1.0"}, asset.id)
    result = p.tls_protocol_version_in(asset, [ev], _ctx(), ["SSLv3", "TLSv1.0", "TLSv1.1"])
    assert result.matched is True
    assert result.discriminator == "TLSv1.0"


def test_tls_protocol_version_in_no_match_for_modern_tls() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _evidence(EvidenceKind.TLS_CERT, {"protocol_version": "TLSv1.3"}, asset.id)
    result = p.tls_protocol_version_in(asset, [ev], _ctx(), ["SSLv3", "TLSv1.0", "TLSv1.1"])
    assert result.matched is False


def test_tls_protocol_version_in_non_list_arg_is_no_match() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _evidence(EvidenceKind.TLS_CERT, {"protocol_version": "TLSv1.0"}, asset.id)
    result = p.tls_protocol_version_in(asset, [ev], _ctx(), "TLSv1.0")
    assert result.matched is False


def _nuclei_tagged_evidence(asset_id: uuid.UUID, template_id: str, tags: list[str]) -> Evidence:
    return _evidence(
        EvidenceKind.NUCLEI_RESULT,
        {"template-id": template_id, "info": {"tags": tags}},
        asset_id,
    )


def test_nuclei_tags_include_match() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _nuclei_tagged_evidence(asset.id, "generic-sqli-error", ["sqli", "generic"])
    result = p.nuclei_tags_include(asset, [ev], _ctx(), ["sqli", "xss", "path-traversal"])
    assert result.matched is True
    assert result.discriminator == "sqli"


def test_nuclei_tags_include_no_match_for_unrelated_tags() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _nuclei_tagged_evidence(asset.id, "tech-detect-nginx", ["tech"])
    result = p.nuclei_tags_include(asset, [ev], _ctx(), ["sqli", "xss", "path-traversal"])
    assert result.matched is False


def test_nuclei_tags_include_non_list_arg_is_no_match() -> None:
    asset = make_asset(AssetType.HTTP_SERVICE, "https://app.example.com")
    ev = _nuclei_tagged_evidence(asset.id, "generic-sqli-error", ["sqli"])
    result = p.nuclei_tags_include(asset, [ev], _ctx(), "sqli")
    assert result.matched is False
