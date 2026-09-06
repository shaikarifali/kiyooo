"""GET /api/teams — backs the web UI's "assign owner" picker (Scorecard/
Bitsight both ship one; kiyooo didn't expose `teams.yaml` over the API at
all until this route). Read-only: `teams.yaml` is still the source of
truth for team definitions, loaded once at startup like every other
org-context file — this just lets the picker search it instead of a human
needing to know exact team ids and member emails by heart.
"""

from __future__ import annotations

from fastapi import APIRouter

from kiyooo.api.deps import OrgContextDep
from kiyooo.api.schemas import TeamSummaryOut

router = APIRouter()


@router.get("", response_model=list[TeamSummaryOut])
async def list_teams(org_context: OrgContextDep) -> list[TeamSummaryOut]:
    return [
        TeamSummaryOut(id=t.id, slack=t.slack, manager=t.manager, members=t.members)
        for t in org_context.teams.teams
    ]
