from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select

from kiyooo.db.models import LlmCallLog
from kiyooo.db.repo.base import Repository


class LlmCallLogRepository(Repository[LlmCallLog]):
    model = LlmCallLog

    async def list_for_finding(self, finding_id: UUID) -> list[LlmCallLog]:
        result = await self._session.execute(
            select(LlmCallLog).where(LlmCallLog.finding_id == finding_id)
        )
        return list(result.scalars().all())

    async def total_cost_for_scan_run(self, scan_run_id: UUID) -> float:
        """`llm/router.py`'s per-run `max_cost_usd` ceiling reads this before
        every call — a run that would exceed the ceiling halts and reports
        rather than silently continuing to spend.
        """
        result = await self._session.execute(
            select(func.coalesce(func.sum(LlmCallLog.cost_usd), 0)).where(
                LlmCallLog.scan_run_id == scan_run_id
            )
        )
        return float(result.scalar_one())

    async def total_cost_all_time(self) -> float:
        """`kiyooo metrics report`'s cost_per_scan_run input (the design
        Stage 11).
        """
        result = await self._session.execute(
            select(func.coalesce(func.sum(LlmCallLog.cost_usd), 0))
        )
        return float(result.scalar_one())
