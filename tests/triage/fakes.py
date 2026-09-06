"""Fakes for `triage/agent.py` integration tests — same in-memory-fake
pattern as `tests/detect/fakes.py`/`tests/enrich/fakes.py`.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING
from uuid import UUID

from kiyooo.llm.provider import LlmProvider, LlmResponse

if TYPE_CHECKING:
    from kiyooo.db.models import FindingStatus, IdentifierVerification, LlmCallLog, Verdict
    from kiyooo.llm.provider import Message


class FakeProvider(LlmProvider):
    def __init__(self, name: str, responses: list[LlmResponse]) -> None:
        self.name = name
        self._responses = list(responses)
        self.calls: list[tuple[list[Message], str]] = []

    async def complete(
        self,
        messages: list[Message],
        *,
        schema: dict[str, object],
        model: str,
        max_tokens: int = 4096,
        tools: list[dict[str, object]] | None = None,
    ) -> LlmResponse:
        self.calls.append((messages, model))
        if not self._responses:
            raise AssertionError(
                f"FakeProvider {self.name!r} ran out of programmed responses "
                f"(call #{len(self.calls)})"
            )
        return self._responses.pop(0)

    async def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        raise NotImplementedError


class FakeVerdictRepository:
    def __init__(self, seed: Verdict | None = None) -> None:
        self._by_hash: dict[str, Verdict] = {}
        if seed is not None:
            self._by_hash[seed.input_hash] = seed

    async def get_by_input_hash(self, input_hash: str) -> Verdict | None:
        return self._by_hash.get(input_hash)

    async def add(self, verdict: Verdict) -> Verdict:
        if verdict.id is None:
            verdict.id = uuid.uuid4()
        self._by_hash[verdict.input_hash] = verdict
        return verdict


class FakeLlmCallLogRepository:
    def __init__(self, spent: float = 0.0) -> None:
        self.logs: list[LlmCallLog] = []
        self._spent = spent

    async def add(self, log: LlmCallLog) -> LlmCallLog:
        self.logs.append(log)
        return log

    async def total_cost_for_scan_run(self, scan_run_id: UUID) -> float:
        return self._spent


class FakeIdentifierVerificationRepository:
    def __init__(self) -> None:
        self.rows: list[IdentifierVerification] = []

    async def add(self, row: IdentifierVerification) -> IdentifierVerification:
        self.rows.append(row)
        return row


class FakeFindingRepositoryForAgent:
    def __init__(self) -> None:
        self.statuses: dict[UUID, FindingStatus] = {}

    async def mark_status(self, finding_id: UUID, status: FindingStatus) -> None:
        self.statuses[finding_id] = status
