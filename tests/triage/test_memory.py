from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kiyooo.db.models import HumanReview, VerdictValue
from kiyooo.triage.memory import embed_and_store_human_review, find_similar_past_decisions


def _review(owner_ref: str, verdict: VerdictValue, embedding: list[float] | None) -> HumanReview:
    return HumanReview(
        id=uuid.uuid4(),
        finding_id=uuid.uuid4(),
        reviewer=owner_ref,
        agreed_with_model=True,
        final_verdict=verdict,
        rationale=f"rationale for {owner_ref}",
        created_at=datetime.now(UTC),
        promote_to_rule=False,
        embedding=embedding,
    )


class _FakeHumanReviewRepository:
    def __init__(self, reviews: list[HumanReview]) -> None:
        self._reviews = reviews
        self.stored_embeddings: dict[uuid.UUID, list[float]] = {}

    async def list_with_embedding_for_category(self, category_id: str) -> list[HumanReview]:
        return [r for r in self._reviews if r.embedding is not None]

    async def set_embedding(self, human_review_id: uuid.UUID, embedding: list[float]) -> None:
        self.stored_embeddings[human_review_id] = embedding


async def _embed_identity(text: str) -> list[float]:
    # Deterministic stand-in: encodes the query as a one-hot-ish vector so
    # cosine similarity has something meaningful to compare against.
    return [1.0, 0.0, 0.0]


async def test_find_similar_past_decisions_ranks_by_cosine_similarity() -> None:
    close = _review("alice", VerdictValue.FALSE_POSITIVE, [0.9, 0.1, 0.0])
    far = _review("bob", VerdictValue.TRUE_POSITIVE, [0.0, 0.0, 1.0])
    repo = _FakeHumanReviewRepository([far, close])

    results = await find_similar_past_decisions(
        "query text", "some-category", human_review_repo=repo, embed=_embed_identity
    )

    assert results[0].rationale == "rationale for alice"
    assert results[-1].rationale == "rationale for bob"


async def test_find_similar_past_decisions_caps_at_top_k() -> None:
    reviews = [
        _review(f"reviewer-{i}", VerdictValue.TRUE_POSITIVE, [1.0, float(i), 0.0]) for i in range(5)
    ]
    repo = _FakeHumanReviewRepository(reviews)

    results = await find_similar_past_decisions(
        "query", "cat", human_review_repo=repo, embed=_embed_identity, top_k=3
    )
    assert len(results) == 3


async def test_find_similar_past_decisions_no_candidates_returns_empty() -> None:
    repo = _FakeHumanReviewRepository([])
    results = await find_similar_past_decisions(
        "query", "cat", human_review_repo=repo, embed=_embed_identity
    )
    assert results == []


async def test_find_similar_past_decisions_ignores_reviews_without_embedding() -> None:
    unembedded = _review("carol", VerdictValue.NOT_EXPLOITABLE, None)
    repo = _FakeHumanReviewRepository([unembedded])
    results = await find_similar_past_decisions(
        "query", "cat", human_review_repo=repo, embed=_embed_identity
    )
    assert results == []


async def test_embed_and_store_human_review_persists_vector() -> None:
    repo = _FakeHumanReviewRepository([])
    review_id = uuid.uuid4()
    await embed_and_store_human_review(
        review_id, "some rationale text", human_review_repo=repo, embed=_embed_identity
    )
    assert repo.stored_embeddings[review_id] == [1.0, 0.0, 0.0]
