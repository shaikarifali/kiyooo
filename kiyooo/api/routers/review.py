"""POST /api/findings/{id}/review — Stage 10's "review actions"
deliverable: the triage queue's agree/disagree action. Writes the same
`human_review` row `kiyooo review` does; unlike the CLI command, this
doesn't generate an embedding or add the finding to the eval corpus —
those are async-friendly batch niceties, not something an HTTP response
should block on. Run `kiyooo review` (or Stage 8's `feedback` sweep) for
that side of it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, HTTPException

from kiyooo.api.deps import SessionDep
from kiyooo.api.schemas import ReviewOut, ReviewRequest
from kiyooo.db.models import HumanReview
from kiyooo.db.repo.finding import FindingRepository
from kiyooo.db.repo.human_review import HumanReviewRepository
from kiyooo.db.repo.verdict import VerdictRepository

router = APIRouter()


@router.post("/findings/{finding_id}/review", response_model=ReviewOut)
async def submit_review(finding_id: UUID, body: ReviewRequest, session: SessionDep) -> ReviewOut:
    finding = await FindingRepository(session).get(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")

    verdicts = await VerdictRepository(session).list_for_finding(finding_id)
    agreed = bool(verdicts) and verdicts[-1].verdict == body.verdict

    review = HumanReview(
        finding_id=finding_id,
        reviewer=body.reviewer,
        agreed_with_model=agreed,
        final_verdict=body.verdict,
        rationale=body.rationale,
        created_at=datetime.now(UTC),
    )
    await HumanReviewRepository(session).add(review)

    return ReviewOut(finding_id=finding_id, agreed_with_model=agreed, final_verdict=body.verdict)
