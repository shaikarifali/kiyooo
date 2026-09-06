from __future__ import annotations

import uuid

from kiyooo.feedback.github_pr import build_branch_name, build_pr_body, build_pr_title
from kiyooo.feedback.promote import PromotionCandidate


def _candidate() -> PromotionCandidate:
    return PromotionCandidate(
        category_id="exposed-database",
        asset_values=["10.0.0.5:3306", "10.0.0.9:3306"],
        reason="internal-only via VPN, confirmed by appsec",
        review_ids=[uuid.uuid4() for _ in range(5)],
    )


def test_pr_title_mentions_category_and_asset_count() -> None:
    title = build_pr_title(_candidate())
    assert "exposed-database" in title
    assert "2 asset(s)" in title


def test_pr_body_includes_reason_and_all_assets() -> None:
    body = build_pr_body(_candidate())
    assert "internal-only via VPN, confirmed by appsec" in body
    assert "10.0.0.5:3306" in body
    assert "10.0.0.9:3306" in body
    assert "proposal, not an" in body


def test_branch_name_is_unique_per_suffix() -> None:
    candidate = _candidate()
    a = build_branch_name(candidate, suffix="aaa111")
    b = build_branch_name(candidate, suffix="bbb222")
    assert a != b
    assert "exposed-database" in a
