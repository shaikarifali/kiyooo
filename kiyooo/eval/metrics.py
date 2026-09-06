"""Eval metrics — pure functions over a list of
(predicted, ground-truth) pairs. `critical_miss_rate` is "the metric that
matters" : a real true positive the model called
`false_positive`/`not_exploitable` when the human label says `critical`.
"""

from __future__ import annotations

from dataclasses import dataclass

_HIGH_CRITICAL = frozenset({"critical", "high"})
_POSITIVE_VERDICTS = frozenset({"true_positive"})
_DISMISSIVE_VERDICTS = frozenset({"false_positive", "not_exploitable"})


@dataclass(frozen=True, slots=True)
class EvalResult:
    case_id: str
    predicted_verdict: str
    predicted_severity: str
    human_verdict: str
    human_severity: str
    cost_usd: float
    latency_ms: int


@dataclass(frozen=True, slots=True)
class EvalMetrics:
    total_cases: int
    precision: float
    recall_high_critical: float
    critical_miss_rate: float
    mean_cost_usd: float
    p50_latency_ms: float
    p95_latency_ms: float


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(int(len(ordered) * pct), len(ordered) - 1)
    return ordered[index]


def compute_metrics(results: list[EvalResult]) -> EvalMetrics:
    if not results:
        return EvalMetrics(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

    predicted_positive = [r for r in results if r.predicted_verdict in _POSITIVE_VERDICTS]
    correct_positive = [r for r in predicted_positive if r.human_verdict in _POSITIVE_VERDICTS]
    precision = len(correct_positive) / len(predicted_positive) if predicted_positive else 0.0

    actual_high_critical_positive = [
        r
        for r in results
        if r.human_severity in _HIGH_CRITICAL and r.human_verdict in _POSITIVE_VERDICTS
    ]
    recall_hits = [
        r for r in actual_high_critical_positive if r.predicted_verdict in _POSITIVE_VERDICTS
    ]
    recall_high_critical = (
        len(recall_hits) / len(actual_high_critical_positive)
        if actual_high_critical_positive
        else 1.0
    )

    actual_critical_positive = [
        r
        for r in results
        if r.human_verdict in _POSITIVE_VERDICTS and r.human_severity == "critical"
    ]
    critical_missed = [
        r for r in actual_critical_positive if r.predicted_verdict in _DISMISSIVE_VERDICTS
    ]
    critical_miss_rate = (
        len(critical_missed) / len(actual_critical_positive) if actual_critical_positive else 0.0
    )

    costs = [r.cost_usd for r in results]
    latencies = [float(r.latency_ms) for r in results]

    return EvalMetrics(
        total_cases=len(results),
        precision=precision,
        recall_high_critical=recall_high_critical,
        critical_miss_rate=critical_miss_rate,
        mean_cost_usd=sum(costs) / len(costs),
        p50_latency_ms=_percentile(latencies, 0.50),
        p95_latency_ms=_percentile(latencies, 0.95),
    )
