"""The 6 ownership sources Stage 3 implements for real (the design's other
2 — DNS audit log and LLM inference — are deferred; see
`kiyooo.db.models.OwnershipSource`'s docstring for why).

Each source function takes an `Asset` plus whatever context it needs and
returns at most one `OwnershipCandidate`, or `None` if it doesn't apply.
`enrich/ownership/__init__.py` calls all six for a given asset and hands the
results to `merge.merge()`.
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from kiyooo.db.models import AssetType, OwnershipSource, OwnerType
from kiyooo.enrich.ownership.merge import OwnershipCandidate

if TYPE_CHECKING:
    from kiyooo.config import OrgContext, TeamDefinition
    from kiyooo.db.models import Asset
    from kiyooo.db.repo.asset import AssetRepository
    from kiyooo.db.repo.ownership import OwnershipRepository
    from kiyooo.enrich.cloud_aws import CloudResourceMatch

# --------------------------------------------------------------------------- #
# manual override — confidence 1.00
# --------------------------------------------------------------------------- #


def manual_override(asset: Asset, org_context: OrgContext) -> OwnershipCandidate | None:
    for override in org_context.ownership_overrides.overrides:
        if override.asset_value == asset.value:
            return OwnershipCandidate(
                source=OwnershipSource.MANUAL,
                owner_type=OwnerType(override.owner_type),
                owner_ref=override.owner_ref,
                confidence=1.00,
                evidence_note=override.note,
            )
    return None


# --------------------------------------------------------------------------- #
# cloud resource tag — confidence 0.95
# --------------------------------------------------------------------------- #


def cloud_tag(asset: Asset, cloud_matches: list[CloudResourceMatch]) -> OwnershipCandidate | None:
    for match in cloud_matches:
        if match.asset_value != asset.value:
            continue
        owner_ref = match.tags.get("Owner") or match.tags.get("Team")
        if owner_ref:
            return OwnershipCandidate(
                source=OwnershipSource.CLOUD_TAG,
                owner_type=OwnerType.TEAM,
                owner_ref=owner_ref,
                confidence=0.95,
                evidence_note=f"{match.resource_type} {match.resource_id} tag",
            )
    return None


# --------------------------------------------------------------------------- #
# terraform state -> repo -> CODEOWNERS — confidence 0.90
# --------------------------------------------------------------------------- #

_TERRAFORM_VALUE_ATTRS: dict[str, str] = {
    "aws_instance": "public_ip",
    "aws_lb": "dns_name",
    "aws_s3_bucket": "bucket",
    "aws_cloudfront_distribution": "domain_name",
}


@dataclass(frozen=True, slots=True)
class TerraformResource:
    asset_value: str
    module_path: str  # "" for the root module


def parse_terraform_state(raw: bytes) -> list[TerraformResource]:
    """Terraform state doesn't record which `.tf` file defined a resource —
    only its module address (e.g. `module.network.aws_instance.web`) — so
    this treats the module path as a proxy for the repo directory that owns
    it (`network/`, here). Root-module resources (no module address) have no
    proxy path and are skipped, not guessed at.
    """
    payload = json.loads(raw)
    resources: list[TerraformResource] = []
    for resource in payload.get("resources", []):
        attr_key = _TERRAFORM_VALUE_ATTRS.get(resource.get("type", ""))
        if attr_key is None:
            continue
        module = resource.get("module", "")
        module_path = module.removeprefix("module.").replace(".", "/")
        for instance in resource.get("instances", []):
            value = instance.get("attributes", {}).get(attr_key)
            if value:
                resources.append(TerraformResource(asset_value=str(value), module_path=module_path))
    return resources


def parse_codeowners(raw: bytes) -> list[tuple[str, str]]:
    """Returns (pattern, owner) pairs in file order. CODEOWNERS' own rule is
    "last matching pattern wins" (same as GitHub/GitLab) — see
    `match_codeowner`, which walks this list in reverse.
    """
    pairs: list[tuple[str, str]] = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        pattern, *owners = parts
        pairs.append((pattern, owners[0].lstrip("@")))
    return pairs


def match_codeowner(module_path: str, codeowners: list[tuple[str, str]]) -> str | None:
    candidate_path = f"{module_path}/main.tf" if module_path else "main.tf"
    for pattern, owner in reversed(codeowners):
        normalized = pattern.lstrip("/")
        if fnmatch.fnmatch(candidate_path, normalized) or fnmatch.fnmatch(
            candidate_path, f"{normalized.rstrip('/')}/*"
        ):
            return owner
    return None


def terraform_codeowners(
    asset: Asset,
    resources: list[TerraformResource],
    codeowners: list[tuple[str, str]],
) -> OwnershipCandidate | None:
    for resource in resources:
        if resource.asset_value != asset.value:
            continue
        owner = match_codeowner(resource.module_path, codeowners)
        if owner:
            return OwnershipCandidate(
                source=OwnershipSource.CODEOWNERS,
                owner_type=OwnerType.TEAM,
                owner_ref=owner,
                confidence=0.90,
                evidence_note=f"terraform module {resource.module_path or '(root)'}",
            )
    return None


# --------------------------------------------------------------------------- #
# teams.yaml dns_pattern / cloud_account / cloud_tags match — confidence 0.80
# --------------------------------------------------------------------------- #


def teams_pattern(
    asset: Asset,
    teams: list[TeamDefinition],
    cloud_matches: list[CloudResourceMatch] | None = None,
) -> OwnershipCandidate | None:
    cloud_matches = cloud_matches or []
    matching_cloud = next((m for m in cloud_matches if m.asset_value == asset.value), None)

    for team in teams:
        if any(fnmatch.fnmatch(asset.value, pattern) for pattern in team.owns.dns_patterns):
            return OwnershipCandidate(
                source=OwnershipSource.TEAM_PATTERN,
                owner_type=OwnerType.TEAM,
                owner_ref=team.id,
                confidence=0.80,
                evidence_note=f"dns_patterns match on {asset.value}",
            )
        if matching_cloud is None:
            continue
        if matching_cloud.account_id in team.owns.cloud_accounts:
            return OwnershipCandidate(
                source=OwnershipSource.TEAM_PATTERN,
                owner_type=OwnerType.TEAM,
                owner_ref=team.id,
                confidence=0.80,
                evidence_note=f"cloud_account match on {matching_cloud.account_id}",
            )
        for key, value in team.owns.cloud_tags.items():
            if matching_cloud.tags.get(key) == value:
                return OwnershipCandidate(
                    source=OwnershipSource.TEAM_PATTERN,
                    owner_type=OwnerType.TEAM,
                    owner_ref=team.id,
                    confidence=0.80,
                    evidence_note=f"cloud_tags match {key}={value}",
                )
    return None


# --------------------------------------------------------------------------- #
# git blame on the deploying manifest — confidence 0.75
# --------------------------------------------------------------------------- #


def build_email_to_team_map(teams: list[TeamDefinition]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for team in teams:
        mapping[str(team.manager).lower()] = team.id
        for member in team.members:
            mapping[str(member).lower()] = team.id
    return mapping


async def git_blame_owner(
    asset: Asset,
    *,
    repo_path: Path,
    manifest_file: str,
    email_to_owner: dict[str, str],
) -> OwnershipCandidate | None:
    """the design doc names this "git blame," but per-line blame output has nothing
    useful to attribute to a whole asset — this uses the manifest file's
    most recent committer instead (`git log -1`), which is what "who owns
    the file that deployed this" actually needs.
    """
    proc = await asyncio.create_subprocess_exec(
        "git",
        "-C",
        str(repo_path),
        "log",
        "-1",
        "--format=%ae",
        "--",
        manifest_file,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _stderr = await proc.communicate()
    if proc.returncode != 0:
        return None

    email = stdout.decode().strip().lower()
    owner_ref = email_to_owner.get(email)
    if not owner_ref:
        return None

    return OwnershipCandidate(
        source=OwnershipSource.GIT_BLAME,
        owner_type=OwnerType.TEAM,
        owner_ref=owner_ref,
        confidence=0.75,
        evidence_note=f"most recent committer of {manifest_file}: {email}",
    )


# --------------------------------------------------------------------------- #
# prior human-confirmed ownership on a sibling asset — confidence 0.70
# --------------------------------------------------------------------------- #


def _parent_domain(value: str) -> str | None:
    """Last two labels, e.g. `api.example.com` -> `example.com`. Naive about
    multi-part TLDs (`.co.uk` etc.) — no public-suffix-list dependency has
    been added for this. Good enough for the common case; a mismatch here
    just means this source doesn't fire, not a wrong attribution.
    """
    labels = value.split(".")
    if len(labels) < 2:
        return None
    return ".".join(labels[-2:])


async def sibling_asset(
    asset: Asset,
    asset_repo: AssetRepository,
    ownership_repo: OwnershipRepository,
) -> OwnershipCandidate | None:
    if asset.type not in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
        return None
    parent = _parent_domain(asset.value)
    if parent is None:
        return None

    siblings = await asset_repo.list_by_value_suffix(f".{parent}")
    for sibling in siblings:
        if sibling.id == asset.id:
            continue
        candidates = await ownership_repo.list_for_asset(sibling.id)
        confirmed = next((c for c in candidates if c.verified_by_human), None)
        if confirmed:
            return OwnershipCandidate(
                source=OwnershipSource.SIBLING_ASSET,
                owner_type=confirmed.owner_type,
                owner_ref=confirmed.owner_ref,
                confidence=0.70,
                evidence_note=f"human-confirmed on sibling {sibling.value}",
            )
    return None
