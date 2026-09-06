"""GET /api/scan-runs — Stage 10."""

from __future__ import annotations

from fastapi import APIRouter, Query

from kiyooo.api.deps import SessionDep
from kiyooo.api.schemas import ScanRunOut
from kiyooo.db.repo.scan_run import ScanRunRepository

router = APIRouter()


@router.get("", response_model=list[ScanRunOut])
async def list_scan_runs(
    session: SessionDep, limit: int = Query(default=20, le=200)
) -> list[ScanRunOut]:
    runs = await ScanRunRepository(session).recent_completed(limit)
    return [ScanRunOut.model_validate(r) for r in runs]
