from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select

from kiyooo.db.models import Verdict, VerdictValue
from kiyooo.db.repo.base import Repository


class VerdictRepository(Repository[Verdict]):
    model = Verdict

    async def get_by_input_hash(self, input_hash: str) -> Verdict | None:
        """`triage/cache.py`'s cache lookup — `input_hash` is `sha256(bundle
        canonical json + prompt_version + model)`, so an identical rescan
        (unchanged evidence, same prompt version, same model) hits this and
        never calls the LLM.
        """
        result = await self._session.execute(
            select(Verdict)
            .where(Verdict.input_hash == input_hash)
            .order_by(Verdict.created_at.desc())
        )
        return result.scalars().first()

    async def list_for_finding(self, finding_id: UUID) -> list[Verdict]:
        result = await self._session.execute(
            select(Verdict).where(Verdict.finding_id == finding_id).order_by(Verdict.created_at)
        )
        return list(result.scalars().all())

    async def count_latest_by_verdict(self) -> dict[VerdictValue, int]:
        """What the model itself concluded, one verdict per finding (its
        most recent, since re-triage after new evidence can change it) —
        the dashboard's "how much of this did the model call noise"
        number. `DISTINCT ON` picks exactly one `Verdict` row per
        `finding_id`, ranked by recency, matching Postgres's own
        recommended idiom for "latest row per group" (this project is
        already Postgres-only — see `test_app.py`'s own note on JSONB/
        pgvector columns).
        """
        latest = (
            select(Verdict.verdict)
            .distinct(Verdict.finding_id)
            .order_by(Verdict.finding_id, Verdict.created_at.desc(), Verdict.id.desc())
            .subquery()
        )
        result = await self._session.execute(
            select(latest.c.verdict, func.count()).group_by(latest.c.verdict)
        )
        return {verdict: count for verdict, count in result.all()}
