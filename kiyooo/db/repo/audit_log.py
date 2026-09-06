from __future__ import annotations

from datetime import datetime

from sqlalchemy import select

from kiyooo.db.models import AuditLog
from kiyooo.db.repo.base import Repository


class AuditLogRepository(Repository[AuditLog]):
    model = AuditLog

    async def since(self, cutoff: datetime, *, limit: int = 100_000) -> list[AuditLog]:
        """`kiyooo audit export`'s data source — Stage 11's
        "audit log export." Append-only, so a time-bounded export is the
        natural shape rather than a full dump every time.
        """
        result = await self._session.execute(
            select(AuditLog)
            .where(AuditLog.occurred_at >= cutoff)
            .order_by(AuditLog.occurred_at)
            .limit(limit)
        )
        return list(result.scalars().all())
