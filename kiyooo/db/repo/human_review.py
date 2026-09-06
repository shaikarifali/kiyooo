from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from kiyooo.db.models import Finding, HumanReview
from kiyooo.db.repo.base import Repository


class HumanReviewRepository(Repository[HumanReview]):
    model = HumanReview

    async def list_with_embedding_for_category(self, category_id: str) -> list[HumanReview]:
        """`triage/memory.py`'s candidate pool for a category's
        `similar_past_decisions` — joins through `Finding` since
        `human_review` itself has no `category_id` column, and excludes
        rows with no embedding yet (nothing to compare against).
        """
        result = await self._session.execute(
            select(HumanReview)
            .join(Finding, Finding.id == HumanReview.finding_id)
            .where(Finding.category_id == category_id, HumanReview.embedding.is_not(None))
        )
        return list(result.scalars().all())

    async def set_embedding(self, human_review_id: UUID, embedding: list[float]) -> None:
        review = await self.get(human_review_id)
        if review is None:
            raise ValueError(f"human_review {human_review_id} not found")
        review.embedding = embedding
        await self._session.flush()

    async def list_unpromoted(self, limit: int = 1000) -> list[HumanReview]:
        """`feedback/promote.py`'s sweep input — excludes reviews already
        folded into a proposed suppression (`promote_to_rule=True`) so a
        repeat sweep doesn't re-propose the same group.
        """
        result = await self._session.execute(
            select(HumanReview).where(HumanReview.promote_to_rule.is_(False)).limit(limit)
        )
        return list(result.scalars().all())

    async def mark_promoted(self, review_ids: list[UUID]) -> None:
        result = await self._session.execute(
            select(HumanReview).where(HumanReview.id.in_(review_ids))
        )
        for review in result.scalars().all():
            review.promote_to_rule = True
        await self._session.flush()

    async def list_all_reviews(self, limit: int = 5000) -> list[HumanReview]:
        """`feedback/agreement.py`'s dashboard input."""
        result = await self._session.execute(select(HumanReview).limit(limit))
        return list(result.scalars().all())

    async def list_for_finding(self, finding_id: UUID) -> list[HumanReview]:
        """The triage page's decision history for one finding — the record
        that a human, not the model, actually closed the loop (invariant
        #4/#6), oldest first so a re-review reads as a timeline.
        """
        result = await self._session.execute(
            select(HumanReview)
            .where(HumanReview.finding_id == finding_id)
            .order_by(HumanReview.created_at)
        )
        return list(result.scalars().all())
