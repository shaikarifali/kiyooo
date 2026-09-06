from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select

from kiyooo.db.models import Finding, FindingDetector, FindingStatus, Severity
from kiyooo.db.repo.base import Repository


class FindingRepository(Repository[Finding]):
    model = Finding

    async def get_by_fingerprint(self, fingerprint: str) -> Finding | None:
        result = await self._session.execute(
            select(Finding).where(Finding.fingerprint == fingerprint)
        )
        return result.scalar_one_or_none()

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
        """Fingerprint is the dedupe key (`Finding.fingerprint` is
        `unique=True`) — a rescan that reproduces the same issue on the same
        asset updates `last_seen`/`scan_run_id` on the existing row rather
        than inserting a duplicate, which is what makes rerunning detection
        idempotent (CLAUDE.md's testing rule: zero spurious rows on a
        repeat scan with unchanged evidence).
        """
        existing = await self.get_by_fingerprint(fingerprint)
        if existing is not None:
            existing.scan_run_id = scan_run_id
            existing.last_seen = observed_at
            existing.cluster_id = cluster_id
            await self._session.flush()
            return existing

        finding = Finding(
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
        return await self.add(finding)

    async def list_for_scan_run(self, scan_run_id: UUID) -> list[Finding]:
        result = await self._session.execute(
            select(Finding).where(Finding.scan_run_id == scan_run_id)
        )
        return list(result.scalars().all())

    async def list_for_scan_run_by_status(
        self, scan_run_id: UUID, status: FindingStatus
    ) -> list[Finding]:
        result = await self._session.execute(
            select(Finding).where(Finding.scan_run_id == scan_run_id, Finding.status == status)
        )
        return list(result.scalars().all())

    async def list_by_status(self, status: FindingStatus) -> list[Finding]:
        result = await self._session.execute(select(Finding).where(Finding.status == status))
        return list(result.scalars().all())

    async def list_by_status_since(self, status: FindingStatus, cutoff: datetime) -> list[Finding]:
        result = await self._session.execute(
            select(Finding).where(Finding.status == status, Finding.first_seen >= cutoff)
        )
        return list(result.scalars().all())

    async def list_for_cluster(self, cluster_id: UUID) -> list[Finding]:
        result = await self._session.execute(
            select(Finding).where(Finding.cluster_id == cluster_id)
        )
        return list(result.scalars().all())

    async def list_filtered(
        self,
        *,
        status: FindingStatus | None = None,
        scan_run_id: UUID | None = None,
        category_id: str | None = None,
        limit: int = 100,
    ) -> list[Finding]:
        """`GET /api/findings`'s query — the change-feed/triage-queue UI's
        default landing views both filter on one or both of `status`/
        `scan_run_id`; `category_id` is the AI attack surface page's own
        filter, one category at a time (same single-value-per-field style
        as the rest of this method, not a new query language).
        """
        stmt = select(Finding).order_by(Finding.last_seen.desc()).limit(limit)
        if status is not None:
            stmt = stmt.where(Finding.status == status)
        if scan_run_id is not None:
            stmt = stmt.where(Finding.scan_run_id == scan_run_id)
        if category_id is not None:
            stmt = stmt.where(Finding.category_id == category_id)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def mark_status(self, finding_id: UUID, status: FindingStatus) -> None:
        finding = await self.get(finding_id)
        if finding is None:
            raise ValueError(f"finding {finding_id} not found")
        finding.status = status
        await self._session.flush()

    async def count_by_status(self) -> dict[FindingStatus, int]:
        """The dashboard's triage funnel — "a human always confirms before
        anything closes," made visible: every row here is
        one of the handful of statuses a finding can actually be in —
        `NEW`/`TRIAGING` awaiting adjudication, `TRIAGED` awaiting a
        human's agree/disagree, everything past that only reachable via
        an explicit human approval (`route/pipeline.py`, `cli.py`'s
        `_decide_approval`).
        """
        result = await self._session.execute(
            select(Finding.status, func.count()).group_by(Finding.status)
        )
        return {status: count for status, count in result.all()}

    async def count_severity_for_status(self, status: FindingStatus) -> dict[Severity, int]:
        """Severity breakdown for one status — the dashboard uses this on
        `ROUTED` to answer "how many of the confirmed true positives were
        critical/high," the number this project actually exists to
        produce.
        """
        result = await self._session.execute(
            select(Finding.raw_severity, func.count())
            .where(Finding.status == status)
            .group_by(Finding.raw_severity)
        )
        return {severity: count for severity, count in result.all()}
