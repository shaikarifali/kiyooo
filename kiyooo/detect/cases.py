"""Fixture format for `kiyooo categories test` (Stage 4 DoD:
"runs each category against labeled fixture assets [should-match /
should-not-match] and passes").

One `<category-id>.cases.yaml` file sits alongside each category YAML in
org-context — org-specific, since categories themselves are org-specific
customization, not something this repo's own `tests/` can
cover for an org's custom `10-custom/` categories.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from pydantic import BaseModel, ConfigDict

from kiyooo.db.models import Asset, AssetType, Evidence, EvidenceKind
from kiyooo.detect.predicates import PredicateContext
from kiyooo.enrich.epss import EpssScore
from kiyooo.enrich.kev import KevCatalog, KevEntry

if TYPE_CHECKING:
    from uuid import UUID


class CaseAsset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: AssetType
    value: str


class CaseEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: EvidenceKind
    content: dict[str, object] = {}
    # Stage 11b's `evidence_injection_suspected` predicate is the first to
    # read this flag — fixtures need a way to set it directly rather than
    # relying on the real injection scanner, which cases.py deliberately
    # doesn't run (a fixture's `content` is hand-authored, not scanned).
    injection_suspected: bool = False


class Case(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    asset: CaseAsset
    evidence: list[CaseEvidence] = []
    # Synthetic KEV/EPSS context for cases exercising `cve_in_kev`/
    # `epss_above` — those predicates need a `PredicateContext` that no
    # fixture asset/evidence pair alone can supply.
    kev_known_exploited_cves: list[str] = []
    epss_scores: dict[str, float] = {}


class CategoryCases(BaseModel):
    model_config = ConfigDict(extra="forbid")

    should_match: list[Case] = []
    should_not_match: list[Case] = []


def cases_path_for(category_source_file: str) -> Path:
    source = Path(category_source_file)
    return source.parent / f"{source.stem}.cases.yaml"


def load_cases(path: Path) -> CategoryCases:
    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return CategoryCases.model_validate(raw)


def build_context(case: Case) -> PredicateContext:
    kev_catalog = None
    if case.kev_known_exploited_cves:
        entries = {
            cve.upper(): KevEntry(
                cve_id=cve.upper(),
                vendor_project="",
                product="",
                vulnerability_name="",
                date_added="",
                known_ransomware_use=False,
            )
            for cve in case.kev_known_exploited_cves
        }
        kev_catalog = KevCatalog(entries=entries, catalog_version="fixture", date_released="")

    epss_scores = {
        cve.upper(): EpssScore(cve_id=cve.upper(), score=score, percentile=0.0)
        for cve, score in case.epss_scores.items()
    }
    return PredicateContext(kev_catalog=kev_catalog, epss_scores=epss_scores)


def build_asset(case_asset: CaseAsset) -> Asset:
    now = datetime.now(UTC)
    return Asset(
        id=uuid.uuid4(),
        type=case_asset.type,
        value=case_asset.value,
        first_seen=now,
        last_seen=now,
        is_active=True,
        confidence_in_scope=1.0,
        scope_reason=None,
        attributes={},
    )


def build_evidence(asset_id: UUID, case_evidence: list[CaseEvidence]) -> list[Evidence]:
    now = datetime.now(UTC)
    return [
        Evidence(
            id=f"ev_case_{i}",
            scan_run_id=uuid.uuid4(),
            asset_id=asset_id,
            kind=item.kind,
            source_tool="fixture",
            collected_at=now,
            content_ref=None,
            content_inline=item.content,
            content_hash="fixture",
            size_bytes=None,
            redacted=False,
            injection_suspected=item.injection_suspected,
        )
        for i, item in enumerate(case_evidence)
    ]
