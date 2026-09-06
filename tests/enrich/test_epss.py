from __future__ import annotations

from pathlib import Path

from kiyooo.enrich.epss import parse_epss_response

FIXTURE = Path(__file__).parent.parent / "fixtures" / "enrich" / "epss_response.json"


def _scores():
    return parse_epss_response(FIXTURE.read_bytes())


def test_parse_epss_response_extracts_all_entries() -> None:
    scores = _scores()
    assert set(scores) == {"CVE-2023-12345", "CVE-2024-99999"}


def test_parse_epss_response_normalizes_cve_id_case() -> None:
    scores = _scores()
    assert "CVE-2024-99999" in scores


def test_parse_epss_response_coerces_string_floats() -> None:
    scores = _scores()
    high = scores["CVE-2023-12345"]
    assert high.score == 0.9452
    assert high.percentile == 0.9912


def test_parse_epss_response_skips_entry_without_cve() -> None:
    raw = b'{"data": [{"epss": "0.5", "percentile": "0.5"}]}'
    assert parse_epss_response(raw) == {}


def test_parse_epss_response_skips_entry_with_unparsable_score() -> None:
    raw = b'{"data": [{"cve": "CVE-2020-0001", "epss": "not-a-number", "percentile": "0.5"}]}'
    assert parse_epss_response(raw) == {}
