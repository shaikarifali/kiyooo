from __future__ import annotations

from pathlib import Path

from kiyooo.metrics import prom


def test_write_textfile_creates_parent_dir_and_content(tmp_path: Path) -> None:
    prom.assets_discovered_total.inc(5)
    prom.findings_by_verdict_total.labels(verdict="true_positive").inc(2)

    out = tmp_path / "nested" / "metrics.prom"
    prom.write_textfile(out)

    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "kiyooo_assets_discovered_total" in text
    assert "kiyooo_findings_by_verdict_total" in text


def test_metric_objects_are_registered_once() -> None:
    # prometheus_client's Counter.collect() reports the family name with
    # any trailing "_total" stripped (it's re-added at exposition-format
    # render time) — this is upstream behavior, not a naming bug here.
    names = {m.name for m in prom.registry.collect()}
    assert "kiyooo_assets_discovered" in names
    assert "kiyooo_scan_duration_seconds" in names
    assert "kiyooo_llm_cost_usd" in names
