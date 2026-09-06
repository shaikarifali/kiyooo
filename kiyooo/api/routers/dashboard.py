"""GET /api/dashboard — Stage 10's cost/agreement dashboard
page. Reuses Stage 8's `feedback/agreement.py` (model/human agreement per
category+model+prompt_version) and Stage 11's `LlmCallLogRepository`
(total spend) directly — same computation the CLI's `kiyooo feedback
agreement` and `kiyooo metrics report` already do, just shaped for one
dashboard page instead of two separate commands.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from kiyooo.api.deps import SessionDep
from kiyooo.db.models import FindingStatus
from kiyooo.db.repo.finding import FindingRepository
from kiyooo.db.repo.human_review import HumanReviewRepository
from kiyooo.db.repo.llm_call_log import LlmCallLogRepository
from kiyooo.db.repo.scan_run import ScanRunRepository
from kiyooo.db.repo.verdict import VerdictRepository
from kiyooo.feedback.agreement import AgreementRecord, compute_agreement

router = APIRouter()


class AgreementRow(BaseModel):
    category_id: str
    model: str
    prompt_version: str
    total: int
    agreed: int
    rate: float


class DashboardOut(BaseModel):
    agreement: list[AgreementRow]
    total_cost_usd: float
    scan_run_count: int
    cost_per_scan_run_usd: float
    # Triage funnel (human-in-the-loop, made visible): every finding sits
    # in one of these statuses right now — nothing skips ahead without a
    # human decision (invariant #4/#6). Keys are `FindingStatus.value`.
    status_counts: dict[str, int]
    # What the model itself concluded, latest verdict per finding — the
    # "how much noise did adjudication call out" number. Keys are
    # `VerdictValue.value`.
    verdict_counts: dict[str, int]
    # Severity breakdown of `ROUTED` findings only — a human already
    # confirmed each of these as a true positive and approved it onward.
    # Keys are `Severity.value`.
    routed_severity_counts: dict[str, int]


@router.get("", response_model=DashboardOut)
async def get_dashboard(session: SessionDep) -> DashboardOut:
    human_review_repo = HumanReviewRepository(session)
    finding_repo = FindingRepository(session)
    verdict_repo = VerdictRepository(session)
    llm_call_log_repo = LlmCallLogRepository(session)
    scan_run_repo = ScanRunRepository(session)

    reviews = await human_review_repo.list_all_reviews()
    records: list[AgreementRecord] = []
    for review in reviews:
        finding = await finding_repo.get(review.finding_id)
        if finding is None:
            continue
        verdicts = await verdict_repo.list_for_finding(review.finding_id)
        if not verdicts:
            continue
        latest = verdicts[-1]
        records.append(
            AgreementRecord(
                category_id=finding.category_id,
                model=latest.model,
                prompt_version=latest.prompt_version,
                agreed=review.agreed_with_model,
            )
        )

    stats = compute_agreement(records)
    agreement_rows = [
        AgreementRow(
            category_id=category_id,
            model=model,
            prompt_version=prompt_version,
            total=stat.total,
            agreed=stat.agreed,
            rate=stat.rate,
        )
        for (category_id, model, prompt_version), stat in stats.items()
    ]

    total_cost = await llm_call_log_repo.total_cost_all_time()
    scan_runs = await scan_run_repo.list_all(limit=100_000)
    scan_run_count = len(scan_runs)
    cost_per_scan_run = total_cost / scan_run_count if scan_run_count else 0.0

    status_counts = await finding_repo.count_by_status()
    verdict_counts = await verdict_repo.count_latest_by_verdict()
    routed_severity_counts = await finding_repo.count_severity_for_status(FindingStatus.ROUTED)

    return DashboardOut(
        agreement=agreement_rows,
        total_cost_usd=total_cost,
        scan_run_count=scan_run_count,
        cost_per_scan_run_usd=cost_per_scan_run,
        status_counts={k.value: v for k, v in status_counts.items()},
        verdict_counts={k.value: v for k, v in verdict_counts.items()},
        routed_severity_counts={k.value: v for k, v in routed_severity_counts.items()},
    )
