"""Loads and matches `detect/fingerprints/ai.yaml` —
passive signature matching against evidence already collected by Stage 1's
recon adapters. A match tags the asset (`enrich/ai_tech.py`); it never
decides true/false-positive on its own — that's still a category
`detect:` block's job (Stage 4), same separation Stage 3's `enrich/tech.py`
tech-tag promotion has from category matching.

Pure and fixture-tested — regex matching only, no model call, no network.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from kiyooo.db.models import EvidenceKind

if TYPE_CHECKING:
    from kiyooo.db.models import Evidence

_CATALOG_PATH = Path(__file__).parent / "fingerprints" / "ai.yaml"


@dataclass(frozen=True, slots=True)
class AiSignature:
    id: str
    label: str
    ports: frozenset[int]
    body_pattern: re.Pattern[str] | None


def _load_signature(raw: dict[str, object]) -> AiSignature:
    ports = raw.get("ports", [])
    body_pattern = raw.get("body_pattern")
    return AiSignature(
        id=str(raw["id"]),
        label=str(raw.get("label", raw["id"])),
        ports=frozenset(int(p) for p in ports) if isinstance(ports, list) else frozenset(),
        body_pattern=re.compile(str(body_pattern)) if body_pattern else None,
    )


def load_catalog(path: Path = _CATALOG_PATH) -> list[AiSignature]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [_load_signature(entry) for entry in raw.get("signatures", [])]


def _port_of(evidence: Evidence) -> int | None:
    content = evidence.content_inline or {}
    port = content.get("port")
    return int(port) if isinstance(port, int) else None


def _body_of(evidence: Evidence) -> str:
    content = evidence.content_inline or {}
    body = content.get("body") or content.get("banner") or ""
    return str(body)


def match_signatures(
    evidence: list[Evidence], catalog: list[AiSignature] | None = None
) -> list[str]:
    """Returns the sorted, deduplicated list of matched signature ids —
    the shape `enrich/ai_tech.py` merges onto `asset.attributes["ai_tech"]`.
    """
    signatures = catalog if catalog is not None else load_catalog()
    relevant = [
        item
        for item in evidence
        if item.kind in (EvidenceKind.PORT_BANNER, EvidenceKind.HTTP_RESPONSE)
    ]

    matched: set[str] = set()
    for item in relevant:
        port = _port_of(item)
        body = _body_of(item)
        for sig in signatures:
            if sig.ports and port in sig.ports:
                matched.add(sig.id)
                continue
            if sig.body_pattern is not None and sig.body_pattern.search(body):
                matched.add(sig.id)
    return sorted(matched)
