"""Prometheus metrics: "assets discovered, findings
by verdict, LLM cost/run, cache hit rate, tool failure rate, scan
duration, critical-miss rate."

Every `kiyooo` invocation is a short-lived batch process, not a
long-running server — there's no persistent `/metrics` endpoint to scrape
here (that's Stage 10's FastAPI surface). Instead this follows Prometheus's
own recommended pattern for batch jobs: write a plain-text exposition-
format file at the end of a run for node_exporter's textfile collector
(`--collector.textfile.directory`) to pick up. One registry per process,
one file write at the end — no pushgateway dependency.
"""

from __future__ import annotations

from pathlib import Path

from prometheus_client import CollectorRegistry, Counter, Histogram, write_to_textfile

registry = CollectorRegistry()

assets_discovered_total = Counter(
    "kiyooo_assets_discovered_total",
    "Assets discovered per scan run",
    registry=registry,
)

findings_by_verdict_total = Counter(
    "kiyooo_findings_by_verdict_total",
    "Triage verdicts issued, by verdict value",
    ["verdict"],
    registry=registry,
)

llm_cost_usd = Histogram(
    "kiyooo_llm_cost_usd",
    "LLM spend for one triage run, in USD",
    buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 50.0),
    registry=registry,
)

cache_hits_total = Counter(
    "kiyooo_triage_cache_hits_total",
    "Findings whose verdict came from the input_hash cache instead of a model call",
    registry=registry,
)

cache_misses_total = Counter(
    "kiyooo_triage_cache_misses_total",
    "Findings that required at least one model call",
    registry=registry,
)

tool_failures_total = Counter(
    "kiyooo_tool_failures_total",
    "Recon adapter runs that failed (timeout, exception, non-zero exit)",
    ["tool"],
    registry=registry,
)

scan_duration_seconds = Histogram(
    "kiyooo_scan_duration_seconds",
    "Wall-clock duration of one `kiyooo scan` invocation",
    buckets=(1, 5, 15, 30, 60, 120, 300, 600, 1800),
    registry=registry,
)


def write_textfile(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_to_textfile(str(path), registry)
