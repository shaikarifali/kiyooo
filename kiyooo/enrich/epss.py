"""FIRST.org EPSS (Exploit Prediction Scoring System) scores (the design
Stage 3) — the other half of "known exploited + EPSS score, not CVSS."

Same shape as `kev.py`: `parse_epss_response` is pure and fixture-tested;
`fetch_epss_scores` is the only thing that touches the network, and nothing
in `tests/` calls it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

EPSS_API_URL = "https://api.first.org/data/v1/epss"
_TIMEOUT_S = 30.0
# FIRST's API accepts a comma-separated cve= list; keep individual requests modest.
_BATCH_SIZE = 100


@dataclass(frozen=True, slots=True)
class EpssScore:
    cve_id: str
    score: float
    percentile: float


def parse_epss_response(raw: bytes) -> dict[str, EpssScore]:
    payload = json.loads(raw)
    scores: dict[str, EpssScore] = {}
    for item in payload.get("data", []):
        cve_id = item.get("cve")
        if not cve_id:
            continue
        try:
            score = float(item.get("epss", 0.0))
            percentile = float(item.get("percentile", 0.0))
        except (TypeError, ValueError):
            continue
        cve_id = cve_id.upper()
        scores[cve_id] = EpssScore(cve_id=cve_id, score=score, percentile=percentile)
    return scores


async def fetch_epss_scores(client: httpx.AsyncClient, cve_ids: list[str]) -> dict[str, EpssScore]:
    scores: dict[str, EpssScore] = {}
    for start in range(0, len(cve_ids), _BATCH_SIZE):
        batch = cve_ids[start : start + _BATCH_SIZE]
        resp = await client.get(EPSS_API_URL, params={"cve": ",".join(batch)}, timeout=_TIMEOUT_S)
        resp.raise_for_status()
        scores.update(parse_epss_response(resp.content))
    return scores
