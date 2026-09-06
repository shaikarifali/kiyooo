"""GET /api/categories, POST /api/categories/{id}/preview — the design
Stage 10's "category editor with live 'what would this match' preview."
The preview reuses `detect/cases.py`'s `Case` shape (asset + evidence +
synthetic KEV/EPSS context) and `detect/evaluate.py`'s real
`evaluate_block` directly — the exact same function `kiyooo categories
test` and live detection both use, so a category that passes the editor's
preview behaves identically once org-context is reloaded for a real scan.
No separate reimplementation to drift out of sync.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from kiyooo.api.deps import OrgContextDep
from kiyooo.detect.cases import Case, build_asset, build_context, build_evidence
from kiyooo.detect.evaluate import UnknownPredicateError, evaluate_block

router = APIRouter()


class CategorySummary(BaseModel):
    id: str
    name: str
    severity_base: str
    enabled: bool


class PreviewResult(BaseModel):
    matched: bool
    discriminator: str | None
    evidence_ids: list[str]
    error: str | None = None


@router.get("", response_model=list[CategorySummary])
async def list_categories(org_context: OrgContextDep) -> list[CategorySummary]:
    return [
        CategorySummary(id=c.id, name=c.name, severity_base=c.severity_base, enabled=c.enabled)
        for c in org_context.categories.values()
    ]


@router.post("/{category_id}/preview", response_model=PreviewResult)
async def preview_category(
    category_id: str, body: Case, org_context: OrgContextDep
) -> PreviewResult:
    category = org_context.categories.get(category_id)
    if category is None:
        raise HTTPException(status_code=404, detail="category not found")

    asset = build_asset(body.asset)
    evidence = build_evidence(asset.id, body.evidence)
    ctx = build_context(body)

    try:
        match = evaluate_block(category.detect, asset, evidence, ctx)
    except UnknownPredicateError as exc:
        return PreviewResult(matched=False, discriminator=None, evidence_ids=[], error=str(exc))

    if match is None:
        return PreviewResult(matched=False, discriminator=None, evidence_ids=[])
    return PreviewResult(
        matched=True, discriminator=match.discriminator, evidence_ids=match.evidence_ids
    )
