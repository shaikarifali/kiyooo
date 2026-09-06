from __future__ import annotations

import pytest

from kiyooo.triage.schema import VerificationRequest
from kiyooo.verify.safety import VerificationRejected, validate_request


def _request(tool: str, args: dict[str, object]) -> VerificationRequest:
    return VerificationRequest(tool=tool, args=args, why="confirm before triage")


# --------------------------------------------------------------------------- #
# unknown tool
# --------------------------------------------------------------------------- #


def test_unknown_tool_rejected() -> None:
    with pytest.raises(VerificationRejected):
        validate_request(_request("shell_exec", {}))


# --------------------------------------------------------------------------- #
# http_probe
# --------------------------------------------------------------------------- #


def test_http_probe_get_allowed() -> None:
    validated = validate_request(
        _request("http_probe", {"host": "app.example.com", "method": "GET", "path": "/"})
    )
    assert validated.tool == "http_probe"
    assert validated.args["method"] == "GET"


def test_http_probe_head_allowed() -> None:
    validated = validate_request(
        _request("http_probe", {"host": "app.example.com", "method": "HEAD", "path": "/login"})
    )
    assert validated.args["method"] == "HEAD"


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_http_probe_write_methods_rejected(method: str) -> None:
    with pytest.raises(VerificationRejected):
        validate_request(
            _request("http_probe", {"host": "app.example.com", "method": method, "path": "/"})
        )


def test_http_probe_unknown_method_rejected() -> None:
    with pytest.raises(VerificationRejected):
        validate_request(
            _request("http_probe", {"host": "app.example.com", "method": "CONNECT", "path": "/"})
        )


def test_http_probe_path_must_start_with_slash() -> None:
    with pytest.raises(VerificationRejected):
        validate_request(
            _request("http_probe", {"host": "app.example.com", "method": "GET", "path": "no-slash"})
        )


def test_http_probe_missing_host_rejected() -> None:
    with pytest.raises(VerificationRejected):
        validate_request(_request("http_probe", {"method": "GET", "path": "/"}))


def test_http_probe_defaults_to_get_and_root_path() -> None:
    validated = validate_request(_request("http_probe", {"host": "app.example.com"}))
    assert validated.args == {"method": "GET", "path": "/"}


# --------------------------------------------------------------------------- #
# tcp_banner / tls_handshake / cert_chain — port validation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("tool", ["tcp_banner", "tls_handshake", "cert_chain"])
def test_port_tools_reject_out_of_range_port(tool: str) -> None:
    with pytest.raises(VerificationRejected):
        validate_request(_request(tool, {"host": "10.0.0.5", "port": 70000}))


@pytest.mark.parametrize("tool", ["tcp_banner", "tls_handshake", "cert_chain"])
def test_port_tools_reject_non_integer_port(tool: str) -> None:
    with pytest.raises(VerificationRejected):
        validate_request(_request(tool, {"host": "10.0.0.5", "port": "not-a-port"}))


def test_tcp_banner_requires_explicit_port() -> None:
    with pytest.raises(VerificationRejected):
        validate_request(_request("tcp_banner", {"host": "10.0.0.5"}))


def test_tcp_banner_valid() -> None:
    validated = validate_request(_request("tcp_banner", {"host": "10.0.0.5", "port": 3306}))
    assert validated.target == "10.0.0.5:3306"


def test_tls_handshake_defaults_to_port_443() -> None:
    validated = validate_request(_request("tls_handshake", {"host": "app.example.com"}))
    assert validated.target == "app.example.com:443"


def test_cert_chain_defaults_to_port_443() -> None:
    validated = validate_request(_request("cert_chain", {"host": "app.example.com"}))
    assert validated.target == "app.example.com:443"


# --------------------------------------------------------------------------- #
# dns_resolve
# --------------------------------------------------------------------------- #


def test_dns_resolve_a_record() -> None:
    validated = validate_request(_request("dns_resolve", {"hostname": "app.example.com"}))
    assert validated.args == {"record_type": "A"}


def test_dns_resolve_aaaa_record() -> None:
    validated = validate_request(
        _request("dns_resolve", {"hostname": "app.example.com", "record_type": "AAAA"})
    )
    assert validated.args == {"record_type": "AAAA"}


def test_dns_resolve_rejects_unknown_record_type() -> None:
    with pytest.raises(VerificationRejected):
        validate_request(
            _request("dns_resolve", {"hostname": "app.example.com", "record_type": "MX"})
        )


# --------------------------------------------------------------------------- #
# nuclei_single
# --------------------------------------------------------------------------- #


def test_nuclei_single_allowlisted_template_accepted() -> None:
    validated = validate_request(
        _request("nuclei_single", {"host": "app.example.com", "template_id": "tech-detect"})
    )
    assert validated.args == {"template_id": "tech-detect"}


def test_nuclei_single_non_allowlisted_template_rejected() -> None:
    with pytest.raises(VerificationRejected):
        validate_request(
            _request("nuclei_single", {"host": "app.example.com", "template_id": "cve-2024-99999"})
        )


def test_nuclei_single_missing_template_id_rejected() -> None:
    with pytest.raises(VerificationRejected):
        validate_request(_request("nuclei_single", {"host": "app.example.com"}))
