from __future__ import annotations

from kiyooo.verify.tools.tls_handshake import parse_handshake_error, parse_handshake_success


def test_parse_handshake_error_detects_certificate_required() -> None:
    content = parse_handshake_error("[SSL: SSLV3_ALERT_CERTIFICATE_REQUIRED] certificate required")
    assert content["requires_client_cert"] is True


def test_parse_handshake_error_detects_handshake_failure() -> None:
    content = parse_handshake_error("[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] handshake failure")
    assert content["requires_client_cert"] is True


def test_parse_handshake_error_unrelated_error_not_flagged() -> None:
    content = parse_handshake_error("[SSL: WRONG_VERSION_NUMBER] wrong version number")
    assert content["requires_client_cert"] is False


def test_parse_handshake_success_no_client_cert_required() -> None:
    content = parse_handshake_success({"subject": (("commonName", "app.example.com"),)})
    assert content["requires_client_cert"] is False
    assert content["peer_cert_present"] is True


def test_parse_handshake_success_no_cert_returned() -> None:
    content = parse_handshake_success(None)
    assert content["peer_cert_present"] is False
