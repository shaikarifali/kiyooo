"""feedback/github_pr.py — opens the PR `feedback/promote.py`'s proposed
suppressions.yaml diff needs a human to merge (invariant #6: a promoted
suppression is proposed, never applied automatically). `build_pr_title`/
`build_pr_body`/`build_branch_name` are pure and fixture-tested; `open_pr`
makes four live GitHub REST calls (get base ref, create branch, get/put
file, create PR) and is untested — the same "real code, live network call
untested" treatment every other GitHub-touching function in this project
gets.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

    from kiyooo.feedback.promote import PromotionCandidate

_API_BASE = "https://api.github.com"


def build_pr_title(candidate: PromotionCandidate) -> str:
    return f"Promote suppression: {candidate.category_id} ({len(candidate.asset_values)} asset(s))"


def build_pr_body(candidate: PromotionCandidate) -> str:
    assets = "\n".join(f"- `{v}`" for v in candidate.asset_values)
    return (
        f"{len(candidate.review_ids)} human reviews marked this category+asset "
        f"combination a false positive for the same reason:\n\n"
        f"> {candidate.reason}\n\n"
        f"**Category:** `{candidate.category_id}`\n\n"
        f"**Assets:**\n{assets}\n\n"
        "Merging this adds a `suppressions.yaml` entry so this stops firing. "
        "Review the reason above before merging — this is a proposal, not an "
        "automatic suppression; nothing changes until this PR is merged."
    )


def build_branch_name(candidate: PromotionCandidate, *, suffix: str) -> str:
    return f"kiyooo/suppress-{candidate.category_id}-{suffix}"


@dataclass(slots=True)
class GithubPrTarget:
    repo: str  # "owner/repo"
    token: str
    base_branch: str = "main"
    file_path: str = "suppressions.yaml"


async def open_pr(
    client: httpx.AsyncClient,
    target: GithubPrTarget,
    *,
    branch_name: str,
    new_file_content: str,
    pr_title: str,
    pr_body: str,
) -> str:
    headers = {
        "Authorization": f"Bearer {target.token}",
        "Accept": "application/vnd.github+json",
    }
    base_ref = await client.get(
        f"{_API_BASE}/repos/{target.repo}/git/ref/heads/{target.base_branch}", headers=headers
    )
    base_ref.raise_for_status()
    base_sha = base_ref.json()["object"]["sha"]

    create_ref = await client.post(
        f"{_API_BASE}/repos/{target.repo}/git/refs",
        json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
        headers=headers,
    )
    create_ref.raise_for_status()

    existing_sha: str | None = None
    existing = await client.get(
        f"{_API_BASE}/repos/{target.repo}/contents/{target.file_path}",
        params={"ref": branch_name},
        headers=headers,
    )
    if existing.status_code == 200:
        existing_sha = existing.json()["sha"]

    put_payload: dict[str, object] = {
        "message": pr_title,
        "content": base64.b64encode(new_file_content.encode("utf-8")).decode("ascii"),
        "branch": branch_name,
    }
    if existing_sha is not None:
        put_payload["sha"] = existing_sha
    put_file = await client.put(
        f"{_API_BASE}/repos/{target.repo}/contents/{target.file_path}",
        json=put_payload,
        headers=headers,
    )
    put_file.raise_for_status()

    create_pr = await client.post(
        f"{_API_BASE}/repos/{target.repo}/pulls",
        json={
            "title": pr_title,
            "body": pr_body,
            "head": branch_name,
            "base": target.base_branch,
        },
        headers=headers,
    )
    create_pr.raise_for_status()
    return str(create_pr.json()["html_url"])
