from __future__ import annotations

import pytest

from kiyooo.db.models import AssetType
from kiyooo.normalize.asset_identity import canonicalize


@pytest.mark.parametrize(
    ("asset_type", "raw", "expected"),
    [
        (AssetType.DOMAIN, "Example.COM", "example.com"),
        (AssetType.DOMAIN, "example.com.", "example.com"),
        (AssetType.SUBDOMAIN, "  WWW.Example.com  ", "www.example.com"),
        (AssetType.SUBDOMAIN, "API.EXAMPLE.COM.", "api.example.com"),
    ],
)
def test_hostname_canonicalization(asset_type: AssetType, raw: str, expected: str) -> None:
    assert canonicalize(asset_type, raw) == expected


def test_two_case_variants_of_same_domain_canonicalize_identically() -> None:
    a = canonicalize(AssetType.DOMAIN, "WWW.Example.COM.")
    b = canonicalize(AssetType.DOMAIN, "www.example.com")
    assert a == b


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("93.184.216.34", "93.184.216.34"),
        ("093.184.216.034", "93.184.216.34"),  # not valid IPv4 -> falls back to lowercase
    ],
)
def test_ip_canonicalization(raw: str, expected: str) -> None:
    result = canonicalize(AssetType.IP, raw)
    # 093... has leading zeros, which Python's ipaddress module rejects as
    # ambiguous (could mean octal) — falls back to a lowercased passthrough,
    # not a crash.
    assert result in (expected, raw.lower())


def test_ipv6_round_trips_through_ip_address_normalization() -> None:
    assert canonicalize(AssetType.IP, "2001:0db8:0000:0000:0000:0000:0000:0001") == ("2001:db8::1")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("HTTPS://Example.COM:443/Path?x=1", "https://example.com/Path?x=1"),
        ("http://example.com:80/", "http://example.com/"),
        ("https://API.example.com:8443/", "https://api.example.com:8443/"),
        ("HTTP://example.com/foo#fragment", "http://example.com/foo"),
    ],
)
def test_url_canonicalization(raw: str, expected: str) -> None:
    assert canonicalize(AssetType.URL, raw) == expected
    assert canonicalize(AssetType.HTTP_SERVICE, raw) == expected


def test_default_port_stripped_but_non_default_port_kept() -> None:
    assert canonicalize(AssetType.URL, "https://example.com:443/") == "https://example.com/"
    assert canonicalize(AssetType.URL, "https://example.com:8443/") == "https://example.com:8443/"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM:443", "example.com:443"),
        ("API.Example.com:8080", "api.example.com:8080"),
    ],
)
def test_host_port_canonicalization(raw: str, expected: str) -> None:
    assert canonicalize(AssetType.TCP_SERVICE, raw) == expected
    assert canonicalize(AssetType.CERT, raw) == expected


def test_unspecified_asset_types_only_strip_whitespace() -> None:
    # No normalization rule exists for these yet — a wrong guess here would
    # silently merge two assets that are actually different, so the
    # conservative default is "don't touch it."
    assert canonicalize(AssetType.REPO, "  Acme/Some-Repo  ") == "Acme/Some-Repo"
    assert canonicalize(AssetType.CLOUD_RESOURCE, "  arn:aws:s3:::Bucket  ") == (
        "arn:aws:s3:::Bucket"
    )


def test_empty_value_returns_empty_string() -> None:
    assert canonicalize(AssetType.DOMAIN, "   ") == ""
