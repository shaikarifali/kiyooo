from __future__ import annotations

from kiyooo.db.models import Verdict
from kiyooo.triage.cache import compute_input_hash, lookup_cached_verdict


class _FakeVerdictRepository:
    def __init__(self, verdict: Verdict | None) -> None:
        self._verdict = verdict
        self.looked_up_hash: str | None = None

    async def get_by_input_hash(self, input_hash: str) -> Verdict | None:
        self.looked_up_hash = input_hash
        return self._verdict


def test_compute_input_hash_deterministic() -> None:
    a = compute_input_hash("{}", prompt_version="v3", model="llama3.1:8b")
    b = compute_input_hash("{}", prompt_version="v3", model="llama3.1:8b")
    assert a == b


def test_compute_input_hash_differs_by_bundle() -> None:
    a = compute_input_hash('{"x":1}', prompt_version="v3", model="llama3.1:8b")
    b = compute_input_hash('{"x":2}', prompt_version="v3", model="llama3.1:8b")
    assert a != b


def test_compute_input_hash_differs_by_prompt_version() -> None:
    a = compute_input_hash("{}", prompt_version="v3", model="llama3.1:8b")
    b = compute_input_hash("{}", prompt_version="v4", model="llama3.1:8b")
    assert a != b


def test_compute_input_hash_differs_by_model() -> None:
    a = compute_input_hash("{}", prompt_version="v3", model="llama3.1:8b")
    b = compute_input_hash("{}", prompt_version="v3", model="claude-sonnet-5")
    assert a != b


async def test_lookup_cached_verdict_delegates_to_repo() -> None:
    repo = _FakeVerdictRepository(None)
    result = await lookup_cached_verdict(repo, "somehash")
    assert result is None
    assert repo.looked_up_hash == "somehash"
