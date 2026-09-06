from __future__ import annotations

from pathlib import Path

from kiyooo.enrich.kev import parse_kev_catalog

FIXTURE = Path(__file__).parent.parent / "fixtures" / "enrich" / "kev_catalog.json"


def _catalog():
    return parse_kev_catalog(FIXTURE.read_bytes())


def test_parse_kev_catalog_captures_metadata() -> None:
    catalog = _catalog()
    assert catalog.catalog_version == "2026.08.01"
    assert catalog.date_released == "2026-08-01T12:00:00.000Z"


def test_parse_kev_catalog_normalizes_cve_id_case() -> None:
    catalog = _catalog()
    assert "CVE-2024-99999" in catalog.entries
    entry = catalog.entries["CVE-2024-99999"]
    assert entry.vendor_project == "Contoso"
    assert entry.product == "Gadget Framework"


def test_is_known_exploited_true_for_present_cve() -> None:
    catalog = _catalog()
    assert catalog.is_known_exploited("CVE-2023-12345") is True


def test_is_known_exploited_is_case_insensitive() -> None:
    catalog = _catalog()
    assert catalog.is_known_exploited("cve-2023-12345") is True


def test_is_known_exploited_false_for_absent_cve() -> None:
    catalog = _catalog()
    assert catalog.is_known_exploited("CVE-1999-0001") is False


def test_known_ransomware_use_flag() -> None:
    catalog = _catalog()
    assert catalog.entries["CVE-2023-12345"].known_ransomware_use is True
    assert catalog.entries["CVE-2024-99999"].known_ransomware_use is False
