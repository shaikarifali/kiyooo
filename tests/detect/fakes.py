"""In-memory fakes for `detect/` tests — Finding/Control/FindingEvidence/
Evidence all use Postgres-only column types, so DB-touching logic is tested
against hand-written fakes matching the real repos' method signatures, the
same pattern as `tests/graph/fakes.py` and `tests/enrich/fakes.py`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from kiyooo.db.models import Control, Evidence, Finding, FindingEvidence

if TYPE_CHECKING:
    from kiyooo.db.models import FindingDetector, FindingEvidenceRole, Severity


class FakeEvidenceRepository:
    def __init__(self, evidence: list[Evidence] | None = None) -> None:
        self._items = list(evidence or [])

    async def for_scan_run(self, scan_run_id: UUID) -> list[Evidence]:
        return [e for e in self._items if e.scan_run_id == scan_run_id]

    async def for_asset(self, asset_id: UUID) -> list[Evidence]:
        return [e for e in self._items if e.asset_id == asset_id]


class FakeControlRepository:
    def __init__(self) -> None:
        self._rows: dict[tuple[UUID, str], Control] = {}

    async def get_for_asset(self, asset_id: UUID, control_id: str) -> Control | None:
        return self._rows.get((asset_id, control_id))

    async def upsert(
        self,
        asset_id: UUID,
        control_id: str,
        *,
        detected_by: str,
        evidence_id: str | None,
        detected_at: datetime,
    ) -> Control:
        key = (asset_id, control_id)
        existing = self._rows.get(key)
        if existing is not None:
            existing.detected_by = detected_by
            existing.evidence_id = evidence_id
            existing.detected_at = detected_at
            return existing

        control = Control(
            id=uuid.uuid4(),
            asset_id=asset_id,
            control_id=control_id,
            detected_by=detected_by,
            evidence_id=evidence_id,
            detected_at=detected_at,
        )
        self._rows[key] = control
        return control

    async def list_for_asset(self, asset_id: UUID) -> list[Control]:
        return [c for c in self._rows.values() if c.asset_id == asset_id]


class FakeFindingRepository:
    def __init__(self) -> None:
        self._by_fingerprint: dict[str, Finding] = {}

    async def get_by_fingerprint(self, fingerprint: str) -> Finding | None:
        return self._by_fingerprint.get(fingerprint)

    async def upsert(
        self,
        *,
        scan_run_id: UUID,
        asset_id: UUID,
        category_id: str,
        raw_severity: Severity,
        title: str,
        description: str | None,
        detector: FindingDetector,
        detector_ref: str | None,
        fingerprint: str,
        cluster_id: UUID,
        observed_at: datetime,
    ) -> Finding:
        existing = self._by_fingerprint.get(fingerprint)
        if existing is not None:
            existing.scan_run_id = scan_run_id
            existing.last_seen = observed_at
            existing.cluster_id = cluster_id
            return existing

        finding = Finding(
            id=uuid.uuid4(),
            scan_run_id=scan_run_id,
            asset_id=asset_id,
            category_id=category_id,
            raw_severity=raw_severity,
            title=title,
            description=description,
            detector=detector,
            detector_ref=detector_ref,
            fingerprint=fingerprint,
            cluster_id=cluster_id,
            first_seen=observed_at,
            last_seen=observed_at,
        )
        self._by_fingerprint[fingerprint] = finding
        return finding

    async def list_for_scan_run(self, scan_run_id: UUID) -> list[Finding]:
        return [f for f in self._by_fingerprint.values() if f.scan_run_id == scan_run_id]

    async def list_for_cluster(self, cluster_id: UUID) -> list[Finding]:
        return [f for f in self._by_fingerprint.values() if f.cluster_id == cluster_id]

    async def list_all(self) -> list[Finding]:
        return list(self._by_fingerprint.values())


class FakeFindingEvidenceRepository:
    def __init__(self) -> None:
        self._rows: dict[tuple[UUID, str], FindingEvidence] = {}

    async def link(self, finding_id: UUID, evidence_id: str, role: FindingEvidenceRole) -> None:
        key = (finding_id, evidence_id)
        existing = self._rows.get(key)
        if existing is not None:
            existing.role = role
            return
        self._rows[key] = FindingEvidence(finding_id=finding_id, evidence_id=evidence_id, role=role)

    async def list_for_finding(self, finding_id: UUID) -> list[FindingEvidence]:
        return [row for row in self._rows.values() if row.finding_id == finding_id]
