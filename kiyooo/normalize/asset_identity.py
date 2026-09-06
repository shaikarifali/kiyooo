"""Asset identity canonicalization.

`Asset` has `UNIQUE(type, value)` — if two tools report the same host as
`WWW.Example.COM.` and `www.example.com`, that constraint doesn't save you;
you get two rows for one asset. Every asset value gets routed through
`canonicalize()` here before it ever reaches `AssetRepository.get_or_create`,
so identity resolution happens once, in one place, not per-adapter.

This is deliberately conservative: a canonicalization rule that's wrong
merges two assets that are actually different, which is worse than a
duplicate row a human can spot. Where the right normalization for an asset
type isn't obvious from the design doc (cloud resources, repos, SaaS tenants, ...),
`canonicalize()` only strips surrounding whitespace and leaves the value
otherwise untouched — narrowing that later is easy; un-merging two
incorrectly-collapsed assets after the fact is not.
"""

from __future__ import annotations

import contextlib
import ipaddress
from urllib.parse import urlsplit, urlunsplit

from kiyooo.db.models import AssetType

_DEFAULT_PORTS = {"http": 80, "https": 443}


def canonicalize(asset_type: AssetType, raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        return value

    if asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
        return _canonicalize_hostname(value)
    if asset_type == AssetType.IP:
        return _canonicalize_ip(value)
    if asset_type in (AssetType.URL, AssetType.HTTP_SERVICE):
        return _canonicalize_url(value)
    if asset_type in (AssetType.TCP_SERVICE, AssetType.CERT):
        return _canonicalize_host_port(value)
    return value


def _canonicalize_hostname(value: str) -> str:
    host = value.lower().rstrip(".")
    if not host:
        return host
    # Not encodable as IDNA (already ASCII in a form the codec rejects, or
    # genuinely malformed) — leave it lowercased rather than raise; this is
    # identity resolution, not validation.
    with contextlib.suppress(UnicodeError):
        host = host.encode("idna").decode("ascii")
    return host


def _canonicalize_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value.lower()


def _canonicalize_url(value: str) -> str:
    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    hostname = _canonicalize_hostname(parts.hostname) if parts.hostname else ""
    port = parts.port
    default_port = _DEFAULT_PORTS.get(scheme)
    netloc = hostname if port is None or port == default_port else f"{hostname}:{port}"
    if parts.username:
        userinfo = parts.username + (f":{parts.password}" if parts.password else "")
        netloc = f"{userinfo}@{netloc}"
    return urlunsplit((scheme, netloc, parts.path, parts.query, ""))


def _canonicalize_host_port(value: str) -> str:
    host, sep, port = value.rpartition(":")
    if not sep:
        return _canonicalize_hostname(value)
    return f"{_canonicalize_hostname(host)}:{port}"
