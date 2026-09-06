"""Repository pattern base. Concrete repos (Stage 1+) subclass this per aggregate —
callers never issue raw ORM queries against `db/models.py` directly.
"""

from __future__ import annotations

from typing import TypeVar
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kiyooo.db.models import Base

ModelT = TypeVar("ModelT", bound=Base)


class Repository[ModelT: Base]:
    model: type[ModelT]

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, id_: UUID | str) -> ModelT | None:
        return await self._session.get(self.model, id_)

    async def add(self, obj: ModelT) -> ModelT:
        self._session.add(obj)
        await self._session.flush()
        return obj

    async def list_all(self, limit: int = 100) -> list[ModelT]:
        result = await self._session.execute(select(self.model).limit(limit))
        return list(result.scalars().all())
