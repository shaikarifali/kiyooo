"""Similar-past-decisions retrieval (Stage 5, §4.1's
`similar_past_decisions`) — pgvector cosine similarity over `human_review`
rows in the same category; top-3 feed directly into the bundle. This is
how the tool learns an org's own judgment calls without fine-tuning.

Embedding generation is provider-pluggable (`EmbedFn`) rather than
hard-wired to one provider, matching `llm/provider.py`'s own abstraction.
Nothing here calls a real embedding model in the test suite — tests supply
a fake `EmbedFn` and hand-built vectors, the same "pure logic, real
provider wired in but untested here" treatment as this stage's other
network-touching pieces.
"""

from __future__ import annotations

import math
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from kiyooo.triage.bundler import SimilarPastDecision

if TYPE_CHECKING:
    from uuid import UUID

    from kiyooo.db.models import HumanReview
    from kiyooo.db.repo.human_review import HumanReviewRepository

EmbedFn = Callable[[str], Awaitable[list[float]]]

_TOP_K = 3


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def _summarize_review(review: HumanReview) -> str:
    return f"{review.final_verdict.value}: {review.rationale}"


async def find_similar_past_decisions(
    finding_summary: str,
    category_id: str,
    *,
    human_review_repo: HumanReviewRepository,
    embed: EmbedFn,
    top_k: int = _TOP_K,
) -> list[SimilarPastDecision]:
    candidates = await human_review_repo.list_with_embedding_for_category(category_id)
    if not candidates:
        return []

    query_vector = await embed(finding_summary)
    scored = [
        (review, _cosine_similarity(query_vector, review.embedding or [])) for review in candidates
    ]
    scored.sort(key=lambda pair: pair[1], reverse=True)

    return [
        SimilarPastDecision(
            finding_summary=_summarize_review(review),
            human_verdict=review.final_verdict.value,
            rationale=review.rationale,
        )
        for review, _score in scored[:top_k]
    ]


async def embed_and_store_human_review(
    human_review_id: UUID,
    text: str,
    *,
    human_review_repo: HumanReviewRepository,
    embed: EmbedFn,
) -> None:
    """Called once, right after a `HumanReview` row is written (Stage 7/8's
    review flow) — generates and persists its embedding so it becomes a
    candidate for future `find_similar_past_decisions` calls.
    """
    vector = await embed(text)
    await human_review_repo.set_embedding(human_review_id, vector)
