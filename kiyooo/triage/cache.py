"""LLM response cache. A rescan that reproduces the
same evidence bundle, prompt version, and model must never call the LLM
again — `input_hash` is the key that makes this possible, and it's what
gives the DoD's "cache hit on identical rescan is 100%" its teeth.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kiyooo.db.models import Verdict
    from kiyooo.db.repo.verdict import VerdictRepository


def compute_input_hash(bundle_canonical_json: str, *, prompt_version: str, model: str) -> str:
    raw = f"{bundle_canonical_json}|{prompt_version}|{model}"
    return hashlib.sha256(raw.encode()).hexdigest()


async def lookup_cached_verdict(verdict_repo: VerdictRepository, input_hash: str) -> Verdict | None:
    return await verdict_repo.get_by_input_hash(input_hash)
