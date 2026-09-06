"""Ownership resolution orchestrator: runs every
applicable source for an asset, persists every candidate it returns as an
`Ownership` row (see `Ownership`'s docstring in `db/models.py` — one row per
source, not a single merged row), and returns the merge outcome for
reporting (`kiyooo assets orphans` / `kiyooo assets disputed-ownership`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from kiyooo.db.models import OwnershipSource
from kiyooo.enrich.ownership import sources
from kiyooo.enrich.ownership.merge import MergeResult, OwnershipCandidate, merge

if TYPE_CHECKING:
    from pathlib import Path
    from uuid import UUID

    from kiyooo.config import OrgContext
    from kiyooo.db.models import Asset
    from kiyooo.db.repo.asset import AssetRepository
    from kiyooo.db.repo.ownership import OwnershipRepository
    from kiyooo.enrich.cloud_aws import CloudResourceMatch
    from kiyooo.enrich.ownership.sources import TerraformResource

__all__ = ["OwnershipEnrichmentContext", "merge_existing", "resolve_ownership"]


@dataclass(frozen=True, slots=True)
class OwnershipEnrichmentContext:
    """Everything the sources need, gathered once per enrichment run rather
    than re-fetched per asset. Every field beyond `org_context` is optional
    in effect — an enrichment run with no cloud credentials or no IaC repo
    configured just means those sources don't fire for anything, not an
    error.
    """

    org_context: OrgContext
    cloud_matches: list[CloudResourceMatch]
    terraform_resources: list[TerraformResource]
    codeowners: list[tuple[str, str]]
    iac_repo_path: Path | None
    iac_manifest_file: str | None
    email_to_owner: dict[str, str]


async def resolve_ownership(
    asset: Asset,
    ctx: OwnershipEnrichmentContext,
    asset_repo: AssetRepository,
    ownership_repo: OwnershipRepository,
) -> MergeResult:
    candidates: list[OwnershipCandidate] = []

    manual = sources.manual_override(asset, ctx.org_context)
    if manual is not None:
        candidates.append(manual)

    tag = sources.cloud_tag(asset, ctx.cloud_matches)
    if tag is not None:
        candidates.append(tag)

    iac = sources.terraform_codeowners(asset, ctx.terraform_resources, ctx.codeowners)
    if iac is not None:
        candidates.append(iac)

    pattern = sources.teams_pattern(asset, ctx.org_context.teams.teams, ctx.cloud_matches)
    if pattern is not None:
        candidates.append(pattern)

    if ctx.iac_repo_path is not None and ctx.iac_manifest_file is not None:
        blame = await sources.git_blame_owner(
            asset,
            repo_path=ctx.iac_repo_path,
            manifest_file=ctx.iac_manifest_file,
            email_to_owner=ctx.email_to_owner,
        )
        if blame is not None:
            candidates.append(blame)

    sibling = await sources.sibling_asset(asset, asset_repo, ownership_repo)
    if sibling is not None:
        candidates.append(sibling)

    for candidate in candidates:
        await ownership_repo.upsert_candidate(
            asset.id,
            candidate.source,
            owner_type=candidate.owner_type,
            owner_ref=candidate.owner_ref,
            confidence=candidate.confidence,
            evidence_note=candidate.evidence_note,
            # A manual override is, by definition, already a human's word —
            # no separate confirmation step makes sense for this source.
            verified_by_human=candidate.source == OwnershipSource.MANUAL,
        )

    return merge(candidates)


async def merge_existing(asset_id: UUID, ownership_repo: OwnershipRepository) -> MergeResult:
    """Merge whatever `Ownership` rows already exist for an asset, without
    re-running any source — what `kiyooo assets orphans`/`disputed-ownership`
    call, since those report on the last `kiyooo enrich` run rather than
    triggering a fresh one.
    """
    rows = await ownership_repo.list_for_asset(asset_id)
    candidates = [
        OwnershipCandidate(
            source=row.source,
            owner_type=row.owner_type,
            owner_ref=row.owner_ref,
            confidence=row.confidence,
            evidence_note=row.evidence_note,
        )
        for row in rows
    ]
    return merge(candidates)
