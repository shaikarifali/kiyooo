from __future__ import annotations

from kiyooo.db.models import AssetType, ChangeEventKind
from kiyooo.diff.rules import detect


def test_new_domain_is_asset_new() -> None:
    assert detect(AssetType.SUBDOMAIN, None, {}) == ChangeEventKind.ASSET_NEW


def test_new_tcp_service_is_port_opened_not_generic_asset_new() -> None:
    assert (
        detect(AssetType.TCP_SERVICE, None, {"port": 8080, "protocol": "tcp"})
        == ChangeEventKind.PORT_OPENED
    )


def test_gone_domain_is_asset_gone() -> None:
    assert detect(AssetType.SUBDOMAIN, {}, None) == ChangeEventKind.ASSET_GONE


def test_gone_tcp_service_is_port_closed() -> None:
    assert (
        detect(AssetType.TCP_SERVICE, {"port": 8080, "protocol": "tcp"}, None)
        == ChangeEventKind.PORT_CLOSED
    )


def test_absent_in_both_scans_is_not_an_event() -> None:
    assert detect(AssetType.TCP_SERVICE, None, None) is None


def test_identical_state_is_not_an_event() -> None:
    state = {"status_code": 200, "tech": ["nginx"], "requires_auth": False}
    assert detect(AssetType.HTTP_SERVICE, state, dict(state)) is None


def test_cert_serial_change_is_cert_changed() -> None:
    before = {"serial_number": "aaa", "subject_cn": "www.example.com"}
    after = {"serial_number": "bbb", "subject_cn": "www.example.com"}
    assert detect(AssetType.CERT, before, after) == ChangeEventKind.CERT_CHANGED


def test_cert_unrelated_field_change_is_not_an_event() -> None:
    before = {"serial_number": "aaa", "not_after": "2026-01-01"}
    after = {"serial_number": "aaa", "not_after": "2026-06-01"}
    assert detect(AssetType.CERT, before, after) is None


def test_403_to_200_is_went_public() -> None:
    before = {"status_code": 403, "tech": [], "requires_auth": True}
    after = {"status_code": 200, "tech": [], "requires_auth": False}
    assert detect(AssetType.HTTP_SERVICE, before, after) == ChangeEventKind.WENT_PUBLIC


def test_auth_removed_without_status_code_change() -> None:
    before = {"status_code": 200, "tech": [], "requires_auth": True}
    after = {"status_code": 200, "tech": [], "requires_auth": False}
    assert detect(AssetType.HTTP_SERVICE, before, after) == ChangeEventKind.AUTH_REMOVED


def test_tech_changed_when_nothing_else_differs() -> None:
    before = {"status_code": 200, "tech": ["nginx"], "requires_auth": False}
    after = {"status_code": 200, "tech": ["nginx", "php"], "requires_auth": False}
    assert detect(AssetType.HTTP_SERVICE, before, after) == ChangeEventKind.TECH_CHANGED


def test_went_public_takes_priority_over_auth_removed_when_both_fire() -> None:
    before = {"status_code": 403, "tech": [], "requires_auth": True}
    after = {"status_code": 200, "tech": [], "requires_auth": False}
    # both conditions technically hold; WENT_PUBLIC is the more specific/
    # security-relevant signal and should win, not fire twice.
    assert detect(AssetType.HTTP_SERVICE, before, after) == ChangeEventKind.WENT_PUBLIC


def test_dod_scenario_exactly_two_events_zero_spurious() -> None:
    """The Stage 2 DoD, directly: a deliberately opened port and a deliberately
    removed auth redirect produce exactly those two change_events, and every
    other asset in the same scan — unchanged — produces zero.
    """
    port_opened = detect(AssetType.TCP_SERVICE, None, {"port": 8080, "protocol": "tcp"})
    auth_removed = detect(
        AssetType.HTTP_SERVICE,
        {"status_code": 200, "tech": ["nginx"], "requires_auth": True},
        {"status_code": 200, "tech": ["nginx"], "requires_auth": False},
    )
    unchanged_cert = detect(
        AssetType.CERT,
        {"serial_number": "aaa", "subject_cn": "www.example.com"},
        {"serial_number": "aaa", "subject_cn": "www.example.com"},
    )
    unchanged_http = detect(
        AssetType.HTTP_SERVICE,
        {"status_code": 200, "tech": ["nginx"], "requires_auth": False},
        {"status_code": 200, "tech": ["nginx"], "requires_auth": False},
    )

    results = [port_opened, auth_removed, unchanged_cert, unchanged_http]
    fired = [r for r in results if r is not None]

    assert port_opened == ChangeEventKind.PORT_OPENED
    assert auth_removed == ChangeEventKind.AUTH_REMOVED
    assert unchanged_cert is None
    assert unchanged_http is None
    assert len(fired) == 2


def test_dod_scenario_rescan_produces_zero_events() -> None:
    """Idempotency: diffing the post-change state against itself (an
    identical rescan) must produce zero events for every asset that fired an
    event the first time, not just the unchanged ones.
    """
    post_change_tcp = {"port": 8080, "protocol": "tcp"}
    post_change_http = {"status_code": 200, "tech": ["nginx"], "requires_auth": False}

    assert detect(AssetType.TCP_SERVICE, post_change_tcp, dict(post_change_tcp)) is None
    assert detect(AssetType.HTTP_SERVICE, post_change_http, dict(post_change_http)) is None
