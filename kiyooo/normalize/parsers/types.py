"""Shared types for evidence-driven edge derivation."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from kiyooo.db.models import AssetEdgeRelation, AssetType
from kiyooo.normalize.asset_identity import canonicalize


@dataclass(frozen=True, slots=True)
class EdgeHint:
    """One candidate `AssetEdge` derived from a single `ParsedEvidence` item.

    `own_is_src=True` means "the evidence's own asset --relation--> the
    related asset"; `False` means the reverse. `related_asset_value` is
    already canonicalized (see `resolve_related_value`) — the caller only
    needs to look it up.
    """

    related_asset_value: str
    relation: AssetEdgeRelation
    own_is_src: bool
    confidence: float = 0.9


def resolve_related_value(value: str) -> str:
    """Evidence content (e.g. dnsx's `host` field) can be a hostname or an IP
    literal, and doesn't say which — pick the right canonicalization by
    testing whether it parses as an IP.
    """
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return canonicalize(AssetType.DOMAIN, value)
    return canonicalize(AssetType.IP, value)
