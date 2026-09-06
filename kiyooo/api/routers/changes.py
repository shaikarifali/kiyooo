"""GET /api/changes — the change feed, Stage 10's default
landing page: "what's new since yesterday."
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Query

from kiyooo.api.deps import SessionDep
from kiyooo.api.schemas import ChangeEventOut
from kiyooo.db.repo.change_event import ChangeEventRepository

router = APIRouter()


@router.get("", response_model=list[ChangeEventOut])
async def list_changes(
    session: SessionDep,
    hours: int = Query(default=24, description="Lookback window; default matches the landing page"),
) -> list[ChangeEventOut]:
    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    events = await ChangeEventRepository(session).since(cutoff)
    return [ChangeEventOut.model_validate(e) for e in events]
